package rakelimit

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNew(t *testing.T) {
	mustNew(t, 1000)
}

const floatBits = 32

type FixedPointTuple struct {
	k, v uint64
}

/* TestBPFFloatToFixedPoint tests the convesion of integers/floats to fixed-point on the
userspace & the bpf side to ensure both convert it in the same way */
func TestBPFFloatToFixedPoint(t *testing.T) {
	rakeLimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	programSpecs, err := rakeLimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}
	defer programSpecs.Close()

	prog := programSpecs.ProgramTestFpCmp

	lookupTable := programSpecs.MapTestSingleResult
	payload := make([]byte, 14)

	// check 27
	if err := lookupTable.Put(uint32(0), floatToFixed(27.0)); err != nil {
		t.Fatal(err)
	}

	res, _, err := prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
	if res == 0 {
		t.Fatal("BPF was unable to compare successfully to 27")
	}

	var fp uint64
	if err := lookupTable.Lookup(uint32(0), &fp); err != nil {
		t.Fatal(err)
	}

	// check if bpf to go works
	fl := fixedToFloat(fp)
	if fl != 19 {
		t.Fatal("Expected 19, got", fl)
	}
}

func TestBPFFEwma(t *testing.T) {
	rakeLimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	programSpecs, err := rakeLimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}
	defer programSpecs.Close()

	prog := programSpecs.ProgramTestEwma

	sr := programSpecs.MapTestSingleResult

	sr.Put(uint32(0), uint64(4294967296000))
	sr.Put(uint32(1), uint64(time.Millisecond))

	payload := make([]byte, 14)

	ret, _, err := prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ret == 0 {
		t.Fatal("Unexpected return from BPF program")
	}
	var result uint64
	if err := sr.Lookup(uint32(0), &result); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkRakelimit(b *testing.B) {
	limit := mustNew(b, math.MaxUint32)

	b.Run("IPv4", func(b *testing.B) {
		packet := mustSerializeLayers(b,
			&layers.Ethernet{
				SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
				DstMAC:       []byte{6, 5, 4, 3, 2, 1},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				SrcIP:    net.IPv4(192, 0, 2, 0),
				DstIP:    net.IPv4(192, 0, 2, 123),
				Protocol: layers.IPProtocolUDP,
			},
			&layers.UDP{
				SrcPort: layers.UDPPort(12345),
				DstPort: layers.UDPPort(443),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		)
		b.ResetTimer()

		_, duration, err := limit.bpfObjects.ProgramProdAnchor.Benchmark(packet, b.N, b.ResetTimer)
		if err != nil {
			b.Fatal(err)
		}

		b.ReportMetric(float64(duration/time.Nanosecond), "ns/op")
	})
}

func mustSerializeLayers(tb testing.TB, layers ...gopacket.SerializableLayer) []byte {
	tb.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		tb.Fatal("Can't serialize layers:", err)
	}

	return buf.Bytes()
}

type testRakelimit struct {
	*Rakelimit
	program *ebpf.Program
	args    *ebpf.Map
	conn    *net.UDPConn
}

const (
	timeArgKey uint32 = iota
	randArgKey
)

func mustNew(tb testing.TB, limit uint32) *testRakelimit {
	tb.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal("Can't listen:", err)
	}
	tb.Cleanup(func() { conn.Close() })

	udp := conn.(*net.UDPConn)
	rake, err := New(udp, limit)
	if err != nil {
		tb.Fatal("Can't create limiter:", err)
	}
	tb.Cleanup(func() { rake.Close() })

	args := rake.bpfObjects.MapTestSingleResult
	if err := args.Put(randArgKey, uint64(math.MaxUint32+1)); err != nil {
		tb.Fatal("Can't update rand:", err)
	}

	return &testRakelimit{rake, rake.bpfObjects.ProgramTestAnchor, args, udp}
}

func (trl *testRakelimit) updateTime(tb testing.TB, now uint64) {
	tb.Helper()

	if now < math.MaxUint64 {
		// Make sure we never use a zero time, since the ewma code
		// assumes that zero means uninitialised.
		now++
	}

	if err := trl.args.Put(timeArgKey, now); err != nil {
		tb.Error("Can't update time:", err)
	}
}

func (trl *testRakelimit) updateRand(tb testing.TB, value uint32) {
	tb.Helper()

	if err := trl.args.Put(randArgKey, uint64(value)); err != nil {
		tb.Error("Can't update rand:", err)
	}
}
