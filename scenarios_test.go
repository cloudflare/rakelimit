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
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
			DstMAC:       []byte{6, 5, 4, 3, 2, 1},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
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

func TestFullySpecifiedAttacker(t *testing.T) {
	traffic := generatePackets(time.Minute,
		packetSpec{
			"attacker", 100, element{
				SourceAddress:      []byte{7, 6, 5, 4},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"insideHH", 5, element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"outsideHH", 5, element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			"noise", 100, element{
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
			"attacker", 100, element{
				SourceAddress:      []byte{7, 6, 5},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"insideHH", 5, element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"outsideHH", 5, element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			"noise", 100, element{
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
			"attacker", 100, element{
				SourceAddress:      []byte{7, 6, 5},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         -1,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"insideHH", 5, element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"outsideHH", 5, element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			"noise", 100, element{
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
			"attacker", 100, element{
				SourceAddress:      []byte{},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"insideHH", 5, element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"outsideHH", 5, element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			"noise", 100, element{
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
			"attacker", 100, element{
				SourceAddress:      []byte{},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         -1,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"insideHH", 5, element{
				SourceAddress:      []byte{7, 6, 5, 1},
				DestinationAddress: []byte{1, 2, 3, 4},
				SourcePort:         53,
				DestinationPort:    443,
			},
		},
		packetSpec{
			"outsideHH", 5, element{
				SourceAddress:      []byte{1, 1, 1, 1},
				DestinationAddress: []byte{6, 7, 8, 9},
				SourcePort:         10,
				DestinationPort:    11,
			},
		},
		packetSpec{
			"noise", 100, element{
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
