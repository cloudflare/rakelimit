package rakelimit

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func TestLoad(t *testing.T) {
	spec, err := loadRake()
	if err != nil {
		t.Fatal(err)
	}

	if err := rewriteConstant(spec, "LIMIT", uint64(100)); err != nil {
		t.Fatal(err)
	}

	t.Run("IPv4", func(t *testing.T) {
		var objs struct {
			Prog *ebpf.Program `ebpf:"filter_ipv4"`
		}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			t.Error(err)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		var objs struct {
			Prog *ebpf.Program `ebpf:"filter_ipv6"`
		}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			t.Error(err)
		}
	})
}

const floatBits = 32

type FixedPointTuple struct {
	k, v uint64
}

/* TestBPFFloatToFixedPoint tests the convesion of integers/floats to fixed-point on the
userspace & the bpf side to ensure both convert it in the same way */
func TestBPFFloatToFixedPoint(t *testing.T) {
	var objs rakeObjects
	if err := loadRakeObjects(&objs, nil); err != nil {
		t.Fatal("Can't load program", err)

	}
	defer objs.Close()

	prog := objs.TestFpCmp
	lookupTable := objs.TestSingleResult
	payload := make([]byte, 14)

	// check 27
	if err := lookupTable.Put(uint32(0), floatToFixed(27.0)); err != nil {
		t.Fatal(err)
	}

	res, _, err := prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
	if res != 0 {
		t.Fatalf("Error on line %d", res)
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
	const (
		rateKey uint32 = iota
		oldTSKey
		newTSKey
	)

	var objs rakeObjects
	if err := loadRakeObjects(&objs, nil); err != nil {
		t.Fatal("Can't load program", err)

	}
	defer objs.Close()

	prog := objs.TestEwma
	sr := objs.TestSingleResult

	sr.Put(rateKey, uint64(50))
	sr.Put(oldTSKey, uint64(346534651))
	sr.Put(newTSKey, uint64(415841581))

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}
	if ret == 0 {
		t.Fatal("Unexpected return from BPF program")
	}

	var result uint64
	if err := sr.Lookup(rateKey, &result); err != nil {
		t.Fatal(err)
	}

	if result != 31 {
		t.Error("Expected 31, got", result)
	}
}

func BenchmarkRakelimit(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		rake := mustNew(b, "127.0.0.1:0", math.MaxUint32)

		packet := mustSerializeLayers(b,
			&layers.Ethernet{
				SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
				DstMAC:       []byte{6, 5, 4, 3, 2, 1},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				Version:  4,
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

		lastRet, duration, err := rake.program.Benchmark(packet, b.N, b.ResetTimer)
		if err != nil {
			b.Fatal(err)
		}

		if lastRet == 0 {
			b.Error("Packet was dropped")
		}

		b.ReportMetric(float64(duration/time.Nanosecond), "ns/op")
	})

	b.Run("IPv6", func(b *testing.B) {
		rake := mustNew(b, "[::1]:0", math.MaxUint32)

		packet := mustSerializeLayers(b,
			&layers.Ethernet{
				SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
				DstMAC:       []byte{6, 5, 4, 3, 2, 1},
				EthernetType: layers.EthernetTypeIPv6,
			},
			&layers.IPv6{
				Version:    6,
				SrcIP:      net.ParseIP("fd::1"),
				DstIP:      net.ParseIP("fc::1337"),
				NextHeader: layers.IPProtocolUDP,
			},
			&layers.UDP{
				SrcPort: layers.UDPPort(12345),
				DstPort: layers.UDPPort(443),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		)
		b.ResetTimer()

		lastRet, duration, err := rake.program.Benchmark(packet, b.N, b.ResetTimer)
		if err != nil {
			b.Fatal(err)
		}

		if lastRet == 0 {
			b.Error("Packet was dropped")
		}

		b.ReportMetric(float64(duration/time.Nanosecond), "ns/op")
	})
}

func mustSerializeLayers(tb testing.TB, layers ...gopacket.SerializableLayer) []byte {
	tb.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		tb.Fatal("Can't serialize layers:", err)
	}

	return buf.Bytes()
}

type testRakelimit struct {
	*Rakelimit
	testProgram *ebpf.Program
	args        *ebpf.Map
	conn        *net.UDPConn
}

const (
	timeArgKey uint32 = iota
	randArgKey
	rateExceededOnLevelKey
)

func mustNew(tb testing.TB, addr string, limit uint32) *testRakelimit {
	tb.Helper()

	conn, err := net.ListenPacket("udp", addr)
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

	prog := rake.bpfObjects.TestIpv4
	if rake.domain == unix.AF_INET6 {
		prog = rake.bpfObjects.TestIpv6
	}

	args := rake.bpfObjects.TestSingleResult
	if err := args.Put(randArgKey, uint64(math.MaxUint32+1)); err != nil {
		tb.Fatal("Can't update rand:", err)
	}

	return &testRakelimit{rake, prog, args, udp}
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

func (trl *testRakelimit) rateExceededOnLevel(tb testing.TB) uint32 {
	tb.Helper()

	var level uint64
	if err := trl.args.Lookup(rateExceededOnLevelKey, &level); err != nil {
		tb.Fatal("Can't lookup drop level:", err)
	}

	return uint32(level)
}
