package targetlimit

func (tl *TargetLimit) stat(key StatParam) uint64 {
	var value MapU64
	tl.statsMap.Lookup(MapU32(key), &value)
	return uint64(value)
}

// get a bunch of stats
func (tl *TargetLimit) GetTotalStat() uint64 {
	return tl.stat(STAT_TOTAL)
}
func (tl *TargetLimit) GetDropDstIPPortStat() uint64 {
	return tl.stat(STAT_DROP_TARGET)
}
func (tl *TargetLimit) GetDropSrcIPStat() uint64 {
	return tl.stat(STAT_DROP_SOURCE)
}
func (tl *TargetLimit) GetDropSrcNetStat() uint64 {
	return tl.stat(STAT_DROP_SOURCENET)
}
func (tl *TargetLimit) GetDropSrcPortStat() uint64 {
	return tl.stat(STAT_DROP_SOURCEPORT)
}
func (tl *TargetLimit) GetErrorStat() uint64 {
	return tl.stat(STAT_ERROR)
}
