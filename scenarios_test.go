package rakelimit

import (
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	"encoding/json"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const rateLimit = 25.0

func getBPFprogram(t *testing.T) (*ebpf.Program, *ebpf.Map) {
	t.Helper()
	rakelimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	rakelimitSpec.CollectionSpec().RewriteConstants(map[string]interface{}{
		"limit": floatToFixed(rateLimit),
	})

	programSpecs, err := rakelimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}

	prog := programSpecs.ProgramTestAnchor
	timeTable := programSpecs.MapTestSingleResult
	t.Cleanup(func() { programSpecs.Close() })
	return prog, timeTable
}

type packet struct {
	element  net.IP
	received time.Time
	key      string
	name     string
}

type Element struct {
	SourceAddress      net.IP
	SourcePort         int
	DestinationAddress net.IP
	DestinationPort    int
}

func (el *Element) Clone() *Element {
	newEl := Element{
		SourcePort:         el.SourcePort,
		DestinationPort:    el.DestinationPort,
		SourceAddress:      make([]byte, len(el.SourceAddress)),
		DestinationAddress: make([]byte, len(el.DestinationAddress)),
	}

	copy(newEl.SourceAddress, el.SourceAddress)
	copy(newEl.DestinationAddress, el.DestinationAddress)

	return &newEl
}

func (el *Element) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d", el.SourceAddress, el.SourcePort, el.DestinationAddress, el.DestinationPort)
}

func TestFullySpecifiedAttacker(t *testing.T) {
	rand.Seed(42)
	now := time.Now()
	duration := time.Minute

	traffic := make([]packet, 0)
	traffic = append(traffic, generateTraffic("attacker", now, duration, 100, 0.0, 0, Element{
		SourceAddress:      []byte{7, 6, 5, 4},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that generalises into attack traffic
	traffic = append(traffic, generateTraffic("insideHH", now.Add(time.Millisecond*100), duration, 5, 0, 0, Element{
		SourceAddress:      []byte{7, 6, 5, 1},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that doesn't generalise into the attack traffic
	traffic = append(traffic, generateTraffic("outsideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{1, 1, 1, 1},
		DestinationAddress: []byte{6, 7, 8, 9},
		SourcePort:         10,
		DestinationPort:    11,
	})...)

	// and some random noise
	traffic = append(traffic, generateTraffic("noise", now, duration, 100, 0, 0, Element{
		SourceAddress:      []byte{8, 7},
		DestinationAddress: []byte{6, 7},
		SourcePort:         -1,
		DestinationPort:    -1,
	})...)

	runScenario(t, "fully_specified_attacker.json", traffic, now, false, true)
}

func TestAttackerSubnet(t *testing.T) {
	rand.Seed(42)
	now := time.Now()
	duration := time.Minute

	traffic := make([]packet, 0)
	traffic = append(traffic, generateTraffic("attacker", now, duration, 100, 0.0, 0.7, Element{
		SourceAddress:      []byte{7, 6, 5},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that generalises into attack traffic
	traffic = append(traffic, generateTraffic("insideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{7, 6, 5, 1},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that doesn't generalise into the attack traffic
	traffic = append(traffic, generateTraffic("outsideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{1, 1, 1, 1},
		DestinationAddress: []byte{6, 7, 8, 9},
		SourcePort:         10,
		DestinationPort:    11,
	})...)

	// and some random noise
	traffic = append(traffic, generateTraffic("noise", now, duration, 100, 0, 0, Element{
		SourceAddress:      []byte{8, 9},
		DestinationAddress: []byte{},
		SourcePort:         -1,
		DestinationPort:    -1,
	})...)

	runScenario(t, "attacker_subnet.json", traffic, now, false, true)
}

func TestAttackerSubnetRandomPort(t *testing.T) {
	rand.Seed(42)
	now := time.Now()
	duration := time.Minute

	traffic := make([]packet, 0)
	traffic = append(traffic, generateTraffic("attacker", now, duration, 100, 0.0, 0.5, Element{
		SourceAddress:      []byte{7, 6, 5},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         -1,
		DestinationPort:    443,
	})...)

	// generate good traffic that generalises into attack traffic
	traffic = append(traffic, generateTraffic("insideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{7, 6, 5, 1},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that doesn't generalise into the attack traffic
	traffic = append(traffic, generateTraffic("outsideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{1, 1, 1, 1},
		DestinationAddress: []byte{6, 7, 8, 9},
		SourcePort:         10,
		DestinationPort:    11,
	})...)

	// and some random noise
	traffic = append(traffic, generateTraffic("noise", now, duration, 100, 0, 0, Element{
		SourceAddress:      []byte{7, 6},
		DestinationAddress: []byte{},
		SourcePort:         -1,
		DestinationPort:    -1,
	})...)

	runScenario(t, "attacker_subnet_random_port.json", traffic, now, false, true)
}

func TestReflectionAttack(t *testing.T) {
	rand.Seed(42)
	now := time.Now()
	duration := time.Minute

	traffic := make([]packet, 0)
	traffic = append(traffic, generateTraffic("attacker", now, duration, 100, 0.0, 0.5, Element{
		SourceAddress:      []byte{},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that generalises into attack traffic
	traffic = append(traffic, generateTraffic("insideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{7, 6, 5, 1},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that doesn't generalise into the attack traffic
	traffic = append(traffic, generateTraffic("outsideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{1, 1, 1, 1},
		DestinationAddress: []byte{6, 7, 8, 9},
		SourcePort:         10,
		DestinationPort:    11,
	})...)

	// and some random noise
	traffic = append(traffic, generateTraffic("noise", now, duration, 100, 0, 0, Element{
		SourceAddress:      []byte{},
		DestinationAddress: []byte{6, 8},
		SourcePort:         -1,
		DestinationPort:    -1,
	})...)

	runScenario(t, "reflection_attack.json", traffic, now, false, true)
}

func TestDestinationOverload(t *testing.T) {
	rand.Seed(42)
	now := time.Now()
	duration := time.Minute

	traffic := make([]packet, 0)
	traffic = append(traffic, generateTraffic("attacker", now, duration, 100, 0.0, 0.5, Element{
		SourceAddress:      []byte{},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         -1,
		DestinationPort:    443,
	})...)

	// generate good traffic that generalises into attack traffic
	traffic = append(traffic, generateTraffic("insideHH", now, duration, 5, 0, 0.5, Element{
		SourceAddress:      []byte{7, 6, 5, 1},
		DestinationAddress: []byte{1, 2, 3, 4},
		SourcePort:         53,
		DestinationPort:    443,
	})...)

	// generate good traffic that doesn't generalise into the attack traffic
	traffic = append(traffic, generateTraffic("outsideHH", now, duration, 5, 0, 0, Element{
		SourceAddress:      []byte{1, 1, 1, 1},
		DestinationAddress: []byte{6, 7, 8, 9},
		SourcePort:         10,
		DestinationPort:    11,
	})...)

	// and some random noise
	traffic = append(traffic, generateTraffic("noise", now, duration, 100, 0, 0, Element{
		SourceAddress:      []byte{7, 6},
		DestinationAddress: []byte{},
		SourcePort:         -1,
		DestinationPort:    -1,
	})...)

	runScenario(t, "destination_overload.json", traffic, now, false, true)
}

func generateTraffic(key string, now time.Time, duration time.Duration, pps int, sinFactor float64, increaseFactor float64, element Element) []packet {
	var packets []packet

	start := now
	target := now.Add(duration)

	for now.Before(target) {
		el := element.Clone() //works
		// var el Element // doesn't work

		source := make([]byte, 4)
		dest := make([]byte, 4)

		// fill up to the right with random bytes
		rand.Read(source[len(el.SourceAddress):])
		rand.Read(dest[len(el.DestinationAddress):])

		// copy over pre-determined part
		copy(source, el.SourceAddress)
		copy(dest, el.DestinationAddress)

		el.SourceAddress = source
		el.DestinationAddress = dest

		// ports
		if el.SourcePort == -1 {
			el.SourcePort = int(rand.Intn(int(math.Pow(2, 16))))
		}
		if el.DestinationPort == -1 {
			el.DestinationPort = int(rand.Intn(int(math.Pow(2, 16))))
		}

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
			gopacket.Payload([]byte{1, 2, 3, 4}))

		packets = append(packets, packet{
			element:  buf.Bytes(),
			received: now,
			key:      key,
			name:     el.String(),
		})

		// initial sleep
		sleep := float64(time.Second.Nanoseconds()) / float64(pps)
		// adjust to sleep factor
		sleep = sleep * (1 - float64(now.Sub(start))/float64(target.Sub(start))*increaseFactor)
		// some noise
		dur := time.Duration((0.9 + rand.Float64()/5) * sleep)
		// add a sinus to have some further periodic fluctuations
		divisor := float64(target.Sub(start)) / (math.Pi * 2)
		// calculate sinResult
		sinResult := math.Sin(float64(now.Sub(start))/divisor) * sinFactor
		dur = time.Duration(float64(dur) * (1 + sinResult))
		now = now.Add(dur)
	}
	return packets
}

type ByTime []packet

func (bt ByTime) Len() int {
	return len(bt)
}

func (bt ByTime) Swap(i, j int) {
	bt[i], bt[j] = bt[j], bt[i]
}

func (bt ByTime) Less(i, j int) bool {
	return bt[i].received.Before(bt[j].received)
}

//TODO: use option struct
func runScenario(t *testing.T, filename string, traffic []packet, start time.Time, addFirst, broken bool) {

	// sort by time
	sort.Sort(ByTime(traffic))

	type PerTime struct {
		total  int
		actual int
	}

	type SingleKey map[string]PerTime

	RatesPerKeyPerTime := make(map[int64]SingleKey)

	var attackerMinTime, attackerMaxTime time.Time

	attackPacketsPassed := 0
	prog, timeMap := getBPFprogram(t)

	// group per time and key
	for _, packet := range traffic {

		if packet.key == "attacker" {
			if attackerMinTime.IsZero() || packet.received.Before(attackerMinTime) {
				attackerMinTime = packet.received
			}
			if packet.received.After(attackerMaxTime) {
				attackerMaxTime = packet.received
			}
		}

		// make sure key's are available first
		if _, ok := RatesPerKeyPerTime[packet.received.Unix()]; !ok {
			RatesPerKeyPerTime[packet.received.Unix()] = make(SingleKey)
		}

		el := RatesPerKeyPerTime[packet.received.Unix()][packet.key]
		timeMap.Put(uint32(0), packet.received.UnixNano())
		verdict, _, err := prog.Test(packet.element)
		if err != nil {
			t.Fatal(err)
		}
		if verdict != 0 {
			//pass
			el.actual++
			if packet.key == "attacker" {
				attackPacketsPassed++
			}
		}
		el.total++
		RatesPerKeyPerTime[packet.received.Unix()][packet.key] = el
	}

	attackerPps := float64(attackPacketsPassed) / attackerMaxTime.Sub(attackerMinTime).Seconds()

	// check if rate limit within expected margin
	if attackerPps > rateLimit*1.10 || attackerPps < rateLimit*0.9 {
		t.Fatal("Attacker traffic outside of range", attackerPps)
	}

	// generate a JSON for debugging/plotting
	var jsonRecords []map[string]uint64

	timestampKey := "unix_timestamp_s"
	for ts, traffics := range RatesPerKeyPerTime {
		record := make(map[string]uint64)
		record[timestampKey] = uint64(ts)
		for k, counts := range traffics {
			record[k+"_actual"] = uint64(counts.actual)
			record[k+"_total"] = uint64(counts.total)
		}
		jsonRecords = append(jsonRecords, record)
	}

	sort.Slice(jsonRecords, func(i, j int) bool {
		return jsonRecords[i][timestampKey] < jsonRecords[j][timestampKey]
	})

	bytes, err := json.Marshal(jsonRecords)
	if err != nil {
		t.Fatal("Can't marshal record:", err)
	}
	ioutil.WriteFile(filename, bytes, 0666)
}
