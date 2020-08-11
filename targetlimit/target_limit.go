package targetlimit

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

//go:generate ebpf2go -clang /usr/bin/clang-7 -env ../src/target_limit.c -- -g -I../src

var (
	byteOrder = binary.LittleEndian
)

type Limit struct {
	PacketsPerSecond, BurstSec float64
}

type TargetLimit struct {
	coll     *ebpf.Collection
	prog     *ebpf.Program
	statsMap *ebpf.Map
	spec     *ebpf.CollectionSpec
}

func (tl *TargetLimit) Prog() *ebpf.Program {
	return tl.prog
}

func pps_burst_to_cost_credit(limit Limit) (uint64, uint64) {
	if limit.PacketsPerSecond == 0 || limit.BurstSec == 0 {
		return 0, 0
	}

	// Cost of packet in nanoseconds
	cost := uint64(1000000000. / limit.PacketsPerSecond)

	// Bucket size in nanoseconds
	credit_max := uint64(limit.BurstSec * float64(cost) * limit.PacketsPerSecond)
	return cost, credit_max
}

func NewTargetLimit(sourcePortLimit, sourceNetLimit, sourceIPLimit, destinationLimit Limit) (*TargetLimit, error) {
	tl := &TargetLimit{}
	var (
		ok  bool
		err error
	)

	tl.spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfElf[:]))
	if err != nil {
		return nil, err
	}

	tl.coll, err = ebpf.NewCollection(tl.spec)
	if err != nil {
		return nil, err
	}

	tl.statsMap, ok = tl.coll.Maps["stats"]
	if !ok {
		tl.coll.Close()
		return nil, fmt.Errorf("no 'stats' symbol found")
	}
	//tl.statsMap.Pin("target_limit")

	// per target
	// calculate cost per packet and credit max per bucket based on target pps and burst seconds (full load?)
	cost, credit_max := pps_burst_to_cost_credit(destinationLimit)
	tl.statsMap.Put(MapU32(PARAM_TARGET_COST), MapU64(cost))
	tl.statsMap.Put(MapU32(PARAM_TARGET_CREDIT_MAX), MapU64(credit_max))

	// per source
	cost, credit_max = pps_burst_to_cost_credit(sourceIPLimit)
	tl.statsMap.Put(MapU32(PARAM_SOURCE_COST), MapU64(cost))
	tl.statsMap.Put(MapU32(PARAM_SOURCE_CREDIT_MAX), MapU64(credit_max))

	// pers sourcenet
	cost, credit_max = pps_burst_to_cost_credit(sourceNetLimit)
	tl.statsMap.Put(MapU32(PARAM_SOURCENET_COST), MapU64(cost))
	tl.statsMap.Put(MapU32(PARAM_SOURCENET_CREDIT_MAX), MapU64(credit_max))

	// per sourceport
	cost, credit_max = pps_burst_to_cost_credit(sourcePortLimit)
	tl.statsMap.Put(MapU32(PARAM_SOURCEPORT_COST), MapU64(cost))
	tl.statsMap.Put(MapU32(PARAM_SOURCEPORT_CREDIT_MAX), MapU64(credit_max))

	tl.prog, ok = tl.coll.Programs["bpf_rate_limit_prod"]

	if !ok {
		tl.coll.Close()
		return nil, fmt.Errorf("Ebpf symbol 'bpf_rate_limit_prod' not found")
	}

	return tl, nil
}

func (tl *TargetLimit) SetProgram(prog string) error {
	var ok bool
	tl.prog, ok = tl.coll.Programs[prog]
	if !ok {
		tl.coll.Close()
		return fmt.Errorf("Ebpf symbol %s not found", prog)
	}
	return nil
}

func (tl *TargetLimit) Program() (*ebpf.Program, error) {
	return tl.prog, nil
}

type MapKey struct {
	ip   [16]byte
	port uint16
}

type MapValue struct {
	last_timestamp uint64
	credit         uint64
}

func (k MapKey) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 18)
	copy(ret[:16], k.ip[:])
	byteOrder.PutUint16(ret[16:18], k.port)
	return ret, nil
}

func (k *MapKey) UnmarshalBinary(data []byte) error {
	copy(k.ip[:], data[:16])
	k.port = byteOrder.Uint16(data[16:18])
	return nil
}

func (v MapValue) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 16)
	byteOrder.PutUint64(ret[0:8], v.last_timestamp)
	byteOrder.PutUint64(ret[8:16], v.credit)
	return ret, nil
}

func (v *MapValue) UnmarshalBinary(data []byte) error {
	v.last_timestamp = byteOrder.Uint64(data[0:8])
	v.credit = byteOrder.Uint64(data[8:16])
	return nil
}

type MapU64 uint64

func (k MapU64) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 8)
	byteOrder.PutUint64(ret, uint64(k))
	return ret, nil
}
func (k *MapU64) UnmarshalBinary(data []byte) error {
	*k = MapU64(byteOrder.Uint64(data))
	return nil
}

type MapU32 uint32

func (k MapU32) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 4)
	byteOrder.PutUint32(ret, uint32(k))
	return ret, nil
}
func (k *MapU32) UnmarshalBinary(data []byte) error {
	*k = MapU32(byteOrder.Uint32(data))
	return nil
}

type StatParam int

const (
	PARAM_TARGET_COST = iota
	PARAM_TARGET_CREDIT_MAX
	PARAM_SOURCE_COST
	PARAM_SOURCE_CREDIT_MAX
	PARAM_SOURCENET_COST
	PARAM_SOURCENET_CREDIT_MAX
	PARAM_SOURCEPORT_COST
	PARAM_SOURCEPORT_CREDIT_MAX
	STAT_TOTAL
	STAT_DROP_TARGET
	STAT_DROP_SOURCE
	STAT_DROP_SOURCENET
	STAT_DROP_SOURCEPORT
	STAT_ERROR
)

func (tl *TargetLimit) Close() {
	tl.coll.Close()
}
