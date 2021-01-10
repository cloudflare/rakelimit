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
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	gopacket.SerializeLayers(buf, opts,
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
	)
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

	var packets []packet
	var prev element
	for _, step := range steps {
		source := step.SourceAddress
		if len(source) < net.IPv4len {
			source = randomIP(rng, prev.SourceAddress, source)
		}

		sourcePort := step.SourcePort
		if sourcePort == -1 {
			sourcePort = randomPort(rng, prev.SourcePort)
		}

		dest := step.DestinationAddress
		if len(dest) < net.IPv4len {
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
	ip := make(net.IP, net.IPv4len)
	copy(ip, template)

	rand.Read(ip[len(template):])
	for bytes.Equal([]byte(prevIP), []byte(ip)) {
		rand.Read(ip[len(template):])
	}

	return ip
}

func TestRate(t *testing.T) {
	const (
		duration = 10 * time.Second
		limit    = 100
	)

	rake := mustNew(t, limit)

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

		verdict, _, err := rake.program.Test(packet.element)
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
		toNet = net.IPv4len - 1 // /24
		limit = 100
	)

	src := net.IP{7, 6, 5, 4}
	srcPort := 53
	dst := net.IP{1, 2, 3, 4}
	dstPort := 443
	wildcard := net.IP{}

	generalisations := []struct {
		level uint32
		element
	}{
		// level 0
		{0, element{src, srcPort, dst, dstPort}},

		// level 1
		{1, element{src[:toNet], srcPort, dst, dstPort}},
		{1, element{src, -1, dst, dstPort}},
		{1, element{src, srcPort, dst, -1}},

		// level 2
		{2, element{wildcard, srcPort, dst, dstPort}},
		{2, element{src[:toNet], -1, dst, dstPort}},
		{2, element{src[:toNet], srcPort, dst, -1}},
		{2, element{src, -1, dst, -1}},

		// level 3
		{3, element{wildcard, -1, dst, dstPort}},
		{3, element{wildcard, srcPort, dst, -1}},
		{3, element{src[:toNet], -1, dst, -1}},

		// level 4
		{4, element{wildcard, -1, dst, -1}},
	}

	for _, gen := range generalisations {
		t.Run(gen.String(), func(t *testing.T) {
			rake := mustNew(t, limit)

			// Drop all packets once rate exceeds limit
			rake.updateRand(t, math.MaxUint32)

			packets := generatePackets(time.Second, packetSpec{
				rate:    limit + 1,
				element: gen.element,
			})

			for i, packet := range packets {
				rake.updateTime(t, packet.received)

				verdict, _, err := rake.program.Test(packet.element)
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

	rake := mustNew(t, limit)
	rake.updateRand(t, math.MaxUint32)
	for i, packet := range packets {
		rake.updateTime(t, packet.received)

		verdict, _, err := rake.program.Test(packet.element)
		if err != nil {
			t.Fatal(err)
		}

		if packet.key == "legit" && verdict == 0 {
			t.Fatalf("Dropped legitimate packet #%d: %v", i, rake.rateExceededOnLevel(t))
		}
	}
}

func TestFullySpecifiedAttacker(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			key:  "attacker",
			rate: 100,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 4},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "insideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "outsideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			key:  "noise",
			rate: 100,
			element: element{
				SourceAddress:      []byte{8, 7},
				DestinationAddress: []byte{6, 7},
				SourcePort:         -1,
				DestinationPort:    -1,
			},
		},
	)

	runScenario(t, rateLimit, traffic)
}

func TestAttackerSubnet(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			key:  "attacker",
			rate: 100,
			element: element{
				SourceAddress:      []byte{7, 6, 5},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "insideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "outsideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			key:  "noise",
			rate: 100,
			element: element{
				SourceAddress:      []byte{8, 9},
				DestinationAddress: []byte{},
				SourcePort:         -1,
				DestinationPort:    -1,
			},
		},
	)

	runScenario(t, rateLimit, traffic)
}

func TestAttackerSubnetRandomPort(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			key:  "attacker",
			rate: 100,
			element: element{
				SourceAddress:      []byte{7, 6, 5},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         -1,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "insideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "outsideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			key:  "noise",
			rate: 100,
			element: element{
				SourceAddress:      []byte{7, 6},
				DestinationAddress: []byte{},
				SourcePort:         -1,
				DestinationPort:    -1,
			},
		},
	)

	runScenario(t, rateLimit, traffic)
}

func TestReflectionAttack(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			key:  "attacker",
			rate: 100,
			element: element{
				SourceAddress:      []byte{},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "insideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "outsideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			key:  "noise",
			rate: 100,
			element: element{
				SourceAddress:      []byte{},
				DestinationAddress: []byte{6, 8},
				SourcePort:         -1,
				DestinationPort:    -1,
			},
		},
	)

	runScenario(t, rateLimit, traffic)
}

func TestDestinationOverload(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			key:  "attacker",
			rate: 100,
			element: element{
				SourceAddress:      []byte{},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         -1,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "insideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			key:  "outsideHH",
			rate: 5,
			element: element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			key:  "noise",
			rate: 100,
			element: element{
				SourceAddress:      []byte{7, 6},
				DestinationAddress: []byte{},
				SourcePort:         -1,
				DestinationPort:    -1,
			},
		},
	)

	runScenario(t, rateLimit, traffic)
}

func runScenario(t *testing.T, rateLimit uint32, traffic []packet) {
	type perKeyStats struct {
		total       int
		actual      int
		first, last uint64
	}

	rates := make(map[string]*perKeyStats)
	rake := mustNew(t, rateLimit)

	for _, packet := range traffic {
		stats := rates[packet.key]
		if stats == nil {
			stats = new(perKeyStats)
			rates[packet.key] = stats
		}

		if stats.first == 0 || packet.received < stats.first {
			stats.first = packet.received
		}
		if packet.received > stats.last {
			stats.last = packet.received
		}

		rake.updateTime(t, packet.received)
		verdict, _, err := rake.program.Test(packet.element)
		if err != nil {
			t.Fatal(err)
		}

		if verdict > 0 {
			stats.actual++
		}
		stats.total++
	}

	limit := float64(rateLimit)
	stats := rates["attacker"]

	duration := time.Duration(stats.last-stats.first) * time.Nanosecond
	actualPPS := float64(stats.actual) / duration.Seconds()

	if actualPPS > limit*1.10 || actualPPS < limit*0.9 {
		t.Errorf("Rate for attacker with limit %.0f is %f", limit, actualPPS)
	}
}
