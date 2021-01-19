package rakelimit

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"

	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const rateLimit = 25.0

var seed int64

func TestMain(m *testing.M) {
	flag.Int64Var(&seed, "seed", 0, "seed for the random number generator")
	flag.Parse()

	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	fmt.Println("Seed is", seed)
	os.Exit(m.Run())
}

type element struct {
	SourceAddress      net.IP
	SourcePort         int
	DestinationAddress net.IP
	DestinationPort    int
}

func (el *element) Clone() *element {
	newEl := element{
		SourcePort:         el.SourcePort,
		DestinationPort:    el.DestinationPort,
		SourceAddress:      make([]byte, len(el.SourceAddress)),
		DestinationAddress: make([]byte, len(el.DestinationAddress)),
	}

	copy(newEl.SourceAddress, el.SourceAddress)
	copy(newEl.DestinationAddress, el.DestinationAddress)

	return &newEl
}

func (el *element) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d", el.SourceAddress, el.SourcePort, el.DestinationAddress, el.DestinationPort)
}

func (el *element) marshal() []byte {
	var packet []gopacket.SerializableLayer
	if len(el.SourceAddress) == net.IPv4len {
		packet = []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
				DstMAC:       []byte{6, 5, 4, 3, 2, 1},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				Version:  4,
				SrcIP:    el.SourceAddress,
				DstIP:    el.DestinationAddress,
				Protocol: layers.IPProtocolUDP,
			},
			&layers.UDP{
				SrcPort: layers.UDPPort(el.SourcePort),
				DstPort: layers.UDPPort(el.DestinationPort),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		}
	} else {
		packet = []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
				DstMAC:       []byte{6, 5, 4, 3, 2, 1},
				EthernetType: layers.EthernetTypeIPv6,
			},
			&layers.IPv6{
				Version:    6,
				SrcIP:      el.SourceAddress,
				DstIP:      el.DestinationAddress,
				NextHeader: layers.IPProtocolUDP,
			},
			&layers.UDP{
				SrcPort: layers.UDPPort(el.SourcePort),
				DstPort: layers.UDPPort(el.DestinationPort),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	gopacket.SerializeLayers(buf, opts, packet...)
	return buf.Bytes()
}

type packet struct {
	element  []byte
	received uint64
	key      string
}

type packetSpec struct {
	key  string
	rate int
	element
}

func generatePackets(duration time.Duration, specs ...packetSpec) []packet {
	// specs describe individual streams of packets that "arrive" concurrently.
	// We need to emit packets from the specs in the correct order, determined
	// by their rate.
	type step struct {
		now uint64
		packetSpec
	}

	var steps []step
	for _, spec := range specs {
		interval := time.Second / time.Duration(spec.rate) / time.Nanosecond
		for i := 0; i < int(duration/interval); i++ {
			steps = append(steps, step{
				uint64(i) * uint64(interval),
				spec,
			})
		}

	}

	sort.Slice(steps, func(i, j int) bool {
		return steps[i].now < steps[j].now
	})

	rng := rand.New(rand.NewSource(seed))
	incompleteIP := func(ip net.IP) bool {
		return len(ip) != net.IPv4len && len(ip) != net.IPv6len
	}

	var packets []packet
	var prev element
	for _, step := range steps {
		source := step.SourceAddress
		if incompleteIP(source) {
			source = randomIP(rng, prev.SourceAddress, source)
		}

		sourcePort := step.SourcePort
		if sourcePort == -1 {
			sourcePort = randomPort(rng, prev.SourcePort)
		}

		dest := step.DestinationAddress
		if incompleteIP(dest) {
			dest = randomIP(rng, prev.DestinationAddress, dest)
		}

		destPort := step.DestinationPort
		if destPort == -1 {
			destPort = randomPort(rng, prev.DestinationPort)
		}

		next := element{
			source, sourcePort,
			dest, destPort,
		}

		packets = append(packets, packet{
			received: step.now,
			key:      step.key,
			element:  next.marshal(),
		})

		prev = next
	}

	return packets
}

func randomPort(rng *rand.Rand, prevPort int) int {
	port := int(rng.Intn(math.MaxUint16))
	for port == prevPort {
		port = int(rng.Intn(math.MaxUint16))
	}
	return port
}

func randomIP(rng *rand.Rand, prevIP net.IP, template net.IP) net.IP {
	if len(template) == cap(template) {
		panic(fmt.Sprint("invalid template:", template))
	}

	ip := make(net.IP, cap(template))
	copy(ip, template)

	rand.Read(ip[len(template):])
	for bytes.Equal([]byte(prevIP), []byte(ip)) {
		rand.Read(ip[len(template):])
	}

	return ip
}

func ipTemplate(ip net.IP, ipLen int) net.IP {
	template := make(net.IP, len(ip), ipLen)
	copy(template, ip)
	return template
}

func TestRate(t *testing.T) {
	const (
		duration = 10 * time.Second
		limit    = 100
	)

	rake := mustNew(t, "127.0.0.1:0", limit)

	packets := generatePackets(duration, packetSpec{
		rate: 2 * limit,
		element: element{
			SourceAddress:      []byte{7, 6, 5, 4},
			DestinationAddress: []byte{1, 2, 3, 4},
			SourcePort:         53,
			DestinationPort:    443,
		},
	})

	var accepted int
	for i, packet := range packets {
		rake.updateTime(t, packet.received)

		verdict, _, err := rake.testProgram.Test(packet.element)
		if err != nil {
			t.Fatal(err)
		}

		if level := rake.rateExceededOnLevel(t); i > 0 && level != 0 {
			t.Fatalf("Packet is matched on level %d instead of 0", level)
		}

		if verdict > 0 {
			accepted++
		}
	}

	acceptedRate := float64(accepted) / duration.Seconds()
	if acceptedRate < limit*0.95 || acceptedRate > limit*1.05 {
		t.Errorf("Didn't match desired rate of %d: %.2f pps accepted", limit, acceptedRate)
	}
}

func TestGeneralisations(t *testing.T) {
	const (
		limit = 100
	)

	ipv6Src := net.ParseIP("1122:3344:5566:7788::aabb")
	ipv6Dst := net.ParseIP("8877:6655:4433:2211::ffee")
	srcPort := 53
	dstPort := 443

	type testcase struct {
		level  uint32
		listen string
		element
	}

	var generalisations []testcase
	for _, proto := range []struct {
		listen      string
		src, srcNet net.IP
		dst         net.IP
		wildcard    net.IP
	}{
		{
			"127.0.0.1:0",
			net.IP{7, 6, 5, 4}, ipTemplate(net.IP{7, 6, 5}, net.IPv4len),
			net.IP{1, 2, 3, 4},
			ipTemplate(nil, net.IPv4len),
		},
		{
			"[::1]:0",
			ipv6Src, ipv6Src[: 64/8 : net.IPv6len],
			ipv6Dst,
			ipTemplate(nil, net.IPv6len),
		},
	} {
		generalisations = append(generalisations,
			// level 0
			testcase{0, proto.listen, element{proto.src, srcPort, proto.dst, dstPort}},

			// level 1
			testcase{1, proto.listen, element{proto.srcNet, srcPort, proto.dst, dstPort}},
			testcase{1, proto.listen, element{proto.src, -1, proto.dst, dstPort}},
			testcase{1, proto.listen, element{proto.src, srcPort, proto.dst, -1}},

			// level 2
			testcase{2, proto.listen, element{proto.wildcard, srcPort, proto.dst, dstPort}},
			testcase{2, proto.listen, element{proto.srcNet, -1, proto.dst, dstPort}},
			testcase{2, proto.listen, element{proto.srcNet, srcPort, proto.dst, -1}},
			testcase{2, proto.listen, element{proto.src, -1, proto.dst, -1}},

			// level 3
			testcase{3, proto.listen, element{proto.wildcard, -1, proto.dst, dstPort}},
			testcase{3, proto.listen, element{proto.wildcard, srcPort, proto.dst, -1}},
			testcase{3, proto.listen, element{proto.srcNet, -1, proto.dst, -1}},

			// level 4
			testcase{4, proto.listen, element{proto.wildcard, -1, proto.dst, -1}},
		)
	}

	for _, gen := range generalisations {
		t.Run(gen.String(), func(t *testing.T) {
			rake := mustNew(t, gen.listen, limit)

			// Drop all packets once rate exceeds limit
			rake.updateRand(t, math.MaxUint32)

			packets := generatePackets(time.Second, packetSpec{
				rate:    limit + 1,
				element: gen.element,
			})

			for i, packet := range packets {
				rake.updateTime(t, packet.received)

				verdict, _, err := rake.testProgram.Test(packet.element)
				if err != nil {
					t.Fatal(err)
				}

				if i == 0 {
					if verdict == 0 {
						t.Fatal("First packet shouldn't be dropped")
					}

					continue
				}

				if verdict > 0 {
					t.Fatalf("Accepted packet #%d", i)
				}

				level := rake.rateExceededOnLevel(t)
				if level != gen.level {
					t.Fatalf("Packet #%d was dropped on level %d instead of %d", i, level, gen.level)
				}
			}
		})
	}
}

func TestAttackPropagation(t *testing.T) {
	const limit = 2645

	packets := generatePackets(10*time.Second,
		packetSpec{
			key:  "attack",
			rate: 3 * limit,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 4},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "legit",
			rate: limit / 2,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 4},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         -1,
				DestinationPort:    443,
			},
		},
	)

	rake := mustNew(t, "127.0.0.1:0", limit)
	rake.updateRand(t, math.MaxUint32)
	for i, packet := range packets {
		rake.updateTime(t, packet.received)

		verdict, _, err := rake.testProgram.Test(packet.element)
		if err != nil {
			t.Fatal(err)
		}

		if packet.key == "legit" && verdict == 0 {
			t.Fatalf("Dropped legitimate packet #%d: %v", i, rake.rateExceededOnLevel(t))
		}
	}
}
