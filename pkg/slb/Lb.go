package slb

import (
	"fmt"
	"github.com/cybwan/l4slb/pkg/ch"
	"golang.org/x/exp/slices"
	"net"

	"github.com/cilium/ebpf"

	"github.com/cybwan/l4slb/pkg/bpf"
	"github.com/cybwan/l4slb/pkg/bpf/adapter"
)

// position of elements inside control vector
const (
	kMacAddrPos uint32 = iota
	kIpv4TunPos
	kIpv6TunPos
	kMainIntfPos
	kHcIntfPos
	kIntrospectionGkPos
)

const (
	kLruCntrOffset uint32 = iota
	kLruMissOffset
	kLruFallbackOffset
	kIcmpTooBigOffset
	kLpmSrcOffset
	kInlineDecapOffset
	kQuicRoutingOffset
	kQuicCidVersionOffset
	kQuicCidDropOffset
	kTcpServerIdRoutingOffset
	kGlobalLruOffset
	kChDropOffset
	kDecapCounterOffset
	kQuicIcmpOffset
	kIcmpPtbV6Offset
	kIcmpPtbV4Offset
)

// LRU map related constants
const (
	kFallbackLruSize = int(1024)
	kMapNoFlags      = int(0)
	kMapNumaNode     = int(4)
	kNoNuma          = int(-1)
)

const (
	V6DADDR             uint8 = 1
	kDeleteXdpProg      int32 = -1
	kMacBytes           int   = 6
	kCtlMapSize         int32 = 16
	kLruPrototypePos    int32 = 0
	kMaxForwardingCores int32 = 128
	kFirstElem          int32 = 0
	kError              int32 = -1

	kMaxQuicId          uint32 = 0x00fffffe // 2^24-2
	kDefaultStatsIndex  uint32 = 0
	kSrcV4Pos           uint32 = 0
	kSrcV6Pos           uint32 = 1
	kRecirculationIndex uint32 = 0
	kHcSrcMacPos        uint32 = 0
	kHcDstMacPos        uint32 = 1

	kEmptyString            = ""
	kFlowDebugParentMapName = "flow_debug_maps"
	kFlowDebugCpuLruName    = "flow_debug_lru"
	kGlobalLruMapName       = "global_lru_maps"
	kGlobalLruPerCpuName    = "global_lru"
)

func NewFlomeshLb(config *FlomeshLbConfig) *FlomeshLb {
	slb := FlomeshLb{
		config:     config,
		vips:       make(map[VipKey]*Vip),
		reals:      make(map[IPAddress]*RealMeta),
		numToReals: make(map[uint32]IPAddress),
		hckeys:     make(map[VipKey]uint32),
	}
	slb.ctlValues = make([]bpf.CtlValue, kCtlMapSize)
	for i := uint32(0); i < slb.config.maxVips; i++ {
		slb.vipNums.PushBack(i)
		if slb.config.enableHc {
			slb.hcKeyNums.PushBack(i)
		}
	}
	for i := uint32(0); i < slb.config.maxReals; i++ {
		slb.realNums.PushBack(i)
	}
	//if !slb.config.testing {
	//	if len(config.defaultMac) != 6 {
	//		log.Fatal().Msg("mac's size is not equal to six byte")
	//	}
	//
	//	ctl := bpf.CtlValue{}
	//	ctl.SetMac(slb.config.defaultMac)
	//	slb.ctlValues[kMacAddrPos] = ctl
	//}
	return &slb
}

func (lb *FlomeshLb) validateAddress(addr string, allowNetAddr bool) AddressType {
	if net.ParseIP(addr) == nil {
		if allowNetAddr && (lb.features.srcRouting || lb.config.testing) {
			if _, _, err := net.ParseCIDR(addr); err == nil {
				return NETWORK
			}
		}
		lb.lbStats.addrValidationFailed++
		log.Error().Msgf("Invalid address: %s", addr)
		return INVALID
	}
	return HOST
}

func (lb *FlomeshLb) ChangeMac(newMac []uint8) bool {
	log.Info().Msg("adding new mac address")
	if len(newMac) != kMacBytes {
		return false
	}
	lb.ctlValues[kMacAddrPos].SetMac(newMac)
	if !lb.config.testing {
		if !lb.config.disableForwarding {
			key := kMacAddrPos
			if err := adapter.BpfUpdateMap(adapter.CtlArray, &key, &lb.ctlValues[kMacAddrPos], ebpf.UpdateAny); err != nil {
				lb.lbStats.bpfFailedCalls++
				log.Error().Msgf("can't add new mac address, error: %v", err)
				return false
			}
		}

		if lb.features.directHealthchecking {
			key := kHcDstMacPos
			if err := adapter.BpfUpdateMap(adapter.HcPcktMacs, &key, &lb.ctlValues[kMacAddrPos], ebpf.UpdateAny); err != nil {
				lb.lbStats.bpfFailedCalls++
				log.Error().Msgf("can't add new mac address for direct healthchecks, error: %v", err)
				return false
			}
		}
	}
	return true
}

func (lb *FlomeshLb) GetMac() []uint8 {
	return lb.ctlValues[kMacAddrPos].GetMac()
}

func (lb *FlomeshLb) GetIndexOfNetworkInterfaces() map[int]uint32 {
	res := make(map[int]uint32)
	res[int(kMainIntfPos)] = lb.ctlValues[kMainIntfPos].GetIfIndex()
	if lb.config.enableHc {
		res[int(kHcIntfPos)] = lb.ctlValues[kHcIntfPos].GetIfIndex()
		if lb.config.tunnelBasedHCEncap {
			res[int(kIpv4TunPos)] = lb.ctlValues[kIpv4TunPos].GetIfIndex()
			res[int(kIpv6TunPos)] = lb.ctlValues[kIpv6TunPos].GetIfIndex()
		}
	}
	return res
}

func (lb *FlomeshLb) AddVip(vip *VipKey, flags uint32) bool {
	if lb.config.disableForwarding {
		log.Info().Msg("Ignoring addVip call on non-forwarding instance")
		return false
	}

	log.Info().Msgf("adding new vip: %s:%d:%d", vip.Address, vip.Port, vip.Proto)

	if lb.vipNums.Len() == 0 {
		log.Error().Msg("exhausted vip's space")
		return false
	}

	if _, exists := lb.vips[*vip]; exists {
		log.Warn().Msg("trying to add already existing vip")
		return false
	}

	vipNum := lb.vipNums.PopFront().(uint32)
	lb.vips[*vip] = NewVip(vipNum, flags, lb.config.chRingSize, lb.config.hashFunction)

	if !lb.config.testing {
		meta := new(bpf.VipMeta)
		meta.VipNum = vipNum
		meta.Flags = flags
		return lb.updateVipMap(ADD, vip, meta)
	}

	return true
}

func (lb *FlomeshLb) AddHcKey(hcKey *VipKey) bool {
	if !lb.config.enableHc {
		log.Error().Msg("Ignoring addHcKey call on non-healthchecking instance")
		return false
	}
	if lb.hcKeyNums.Len() == 0 {
		log.Error().Msg("exhausted hc key's space")
		return false
	}
	if _, exists := lb.hckeys[*hcKey]; exists {
		log.Error().Msg("trying to add already existing hc key")
		return false
	}
	hcKeyNum := lb.hcKeyNums.PopFront().(uint32)
	lb.hckeys[*hcKey] = hcKeyNum
	if !lb.config.testing {
		return lb.updateHcKeyMap(ADD, hcKey, hcKeyNum)
	}
	return true
}

func (lb *FlomeshLb) ChangeHashFunctionForVip(vip *VipKey, hfunc ch.HashFunction) bool {
	if lb.config.disableForwarding {
		log.Error().Msg("Ignoring addVip call on non-forwarding instance")
		return false
	}
	if net.ParseIP(vip.Address) == nil {
		log.Error().Msgf("Invalid Vip address: %s", vip.Address)
		return false
	}
	entry, exists := lb.vips[*vip]
	if !exists {
		log.Error().Msg("trying to change non existing vip")
		return false
	}

	entry.SetHashFunction(hfunc)
	positions := entry.recalculateHashRing()
	lb.programHashRing(positions, entry.GetNum())
	return true
}

func (lb *FlomeshLb) programHashRing(chPositions []RealPos, vipNum uint32) {
	if len(chPositions) == 0 {
		return
	}
	if !lb.config.testing {
		updateSize := len(chPositions)
		keys := make([]uint32, updateSize)
		values := make([]uint32, updateSize)

		for i := 0; i < updateSize; i++ {
			keys[i] = vipNum*lb.config.chRingSize + chPositions[i].pos
			values[i] = chPositions[i].real
		}

		if err := adapter.BpfUpdateMapBatch(adapter.ChRings, keys, values, updateSize); err != nil {
			lb.lbStats.bpfFailedCalls++
			log.Error().Msgf("can't update ch ring, error: %v", err)
		}
	}
}

func (lb *FlomeshLb) DelVip(vip *VipKey) bool {
	if lb.config.disableForwarding {
		log.Info().Msg("Ignoring delVip call on non-forwarding instance")
		return false
	}

	log.Info().Msgf("deleting vip: %s:%d:%d", vip.Address, vip.Port, vip.Proto)

	entry, exists := lb.vips[*vip]
	if !exists {
		log.Warn().Msg("trying to delete non-existing vip")
		return false
	}

	for rnum, _ := range entry.reals {
		realAddr := lb.numToReals[rnum]
		lb.decreaseRefCountForReal(realAddr)
	}

	lb.vipNums.PushBack(entry.num)

	if !lb.config.testing {
		lb.updateVipMap(DEL, vip, nil)
	}
	delete(lb.vips, *vip)
	return true
}

func (lb *FlomeshLb) DelHcKey(hcKey *VipKey) bool {
	if !lb.config.enableHc {
		log.Error().Msg("Ignoring delHcKey call on non-healthchecking instance")
		return false
	}

	log.Info().Msgf("deleting hc_key: %s:%d:%d", hcKey.Address, hcKey.Port, hcKey.Proto)

	entry, exists := lb.hckeys[*hcKey]
	if !exists {
		log.Info().Msg("trying to delete non-existing hc_key")
		return false
	}

	lb.hcKeyNums.PushBack(entry)
	delete(lb.hckeys, *hcKey)

	if !lb.config.testing {
		lb.updateHcKeyMap(DEL, hcKey, 0)
	}

	return true
}

func (lb *FlomeshLb) GetAllVips() []VipKey {
	vips := make([]VipKey, 0)
	if lb.config.disableForwarding {
		log.Error().Msg("getAllVips called on non-forwarding instance")
		return vips
	}
	for k := range lb.vips {
		vips = append(vips, k)
	}
	return vips
}

func (lb *FlomeshLb) GetVipFlags(vip *VipKey) (uint32, error) {
	if lb.config.disableForwarding {
		log.Error().Msg("getVipFlags called on non-forwarding instance")
		return 0, fmt.Errorf("getVipFlags called on non-forwarding instance")
	}
	entry, exists := lb.vips[*vip]
	if !exists {
		return 0, fmt.Errorf("trying to get flags from non-existing vip: %s", vip.Address)
	}
	return entry.GetFlags(), nil
}

func (lb *FlomeshLb) ModifyVip(vip *VipKey, flag uint32, set bool) bool {
	log.Info().Msgf("modifying vip: %s:%d:%d", vip.Address, vip.Port, vip.Proto)
	entry, exists := lb.vips[*vip]
	if !exists {
		log.Info().Msgf("trying to modify non-existing vip: %s", vip.Address)
		return false
	}
	if set {
		entry.SetFlags(flag)
	} else {
		entry.UnsetFlags(flag)
	}
	if !lb.config.testing {
		meta := new(bpf.VipMeta)
		meta.VipNum = entry.GetNum()
		meta.Flags = entry.GetFlags()
		return lb.updateVipMap(ADD, vip, meta)
	}
	return true
}

func (lb *FlomeshLb) AddRealForVip(real *NewReal, vip *VipKey) bool {
	if lb.config.disableForwarding {
		log.Error().Msg("addRealForVip called on non-forwarding instance")
		return false
	}

	reals := []NewReal{*real}
	return lb.ModifyRealsForVip(ADD, reals, vip)
}

func (lb *FlomeshLb) DelRealForVip(real *NewReal, vip *VipKey) bool {
	if lb.config.disableForwarding {
		log.Error().Msg("delRealForVip called on non-forwarding instance")
		return false
	}

	reals := []NewReal{*real}
	return lb.ModifyRealsForVip(DEL, reals, vip)
}

func (lb *FlomeshLb) ModifyReal(real string, flags uint8, set bool) bool {
	if lb.config.disableForwarding {
		log.Error().Msg("modifyReal called on non-forwarding instance")
		return false
	}

	if net.ParseIP(real) == nil {
		log.Error().Msgf("invalid real's address: %s", real)
		return false
	}

	log.Info().Msgf("modifying real: %s", real)

	raddr := IPAddress(real)
	entry, exists := lb.reals[raddr]
	if !exists {
		log.Info().Msgf("trying to modify non-existing real: %s", real)
		return false
	}

	flags &= ^V6DADDR // to keep IPv4/IPv6 specific flag
	if set {
		entry.flags |= flags
	} else {
		entry.flags &= ^flags
	}
	lb.reals[raddr].flags = entry.flags
	if !lb.config.testing {
		lb.updateRealsMap(raddr, entry.num, entry.flags)
	}
	return true
}

func (lb *FlomeshLb) ModifyRealsForVip(action ModifyAction, reals []NewReal, vip *VipKey) bool {
	if lb.config.disableForwarding {
		log.Error().Msg("modifyRealsForVip called on non-forwarding instance")
		return false
	}
	ureal := UpdateReal{}
	ureal.action = action

	ureals := make([]UpdateReal, 0)

	entry, exists := lb.vips[*vip]
	if !exists {
		log.Info().Msgf("trying to modify reals for non existing vip:: %s", vip.Address)
		return false
	}
	curReals := entry.getReals()

	for _, r := range reals {
		if net.ParseIP(r.Address) == nil {
			log.Error().Msgf("Invalid real's address: %s", r.Address)
			continue
		}
		log.Info().Msgf("modifying real: %s with weight %d for vip %s:%d:%d",
			r.Address, r.Weight, vip.Address, vip.Port, vip.Proto)

		raddr := IPAddress(r.Address)
		if action == DEL {
			rentry, found := lb.reals[raddr]
			if !found {
				log.Info().Msg("trying to delete non-existing real")
				continue
			}

			if !slices.Contains(curReals, rentry.num) {
				log.Info().Msgf("trying to delete non-existing real for the VIP: %s", vip.Address)
				continue
			}
			ureal.updatedReal.Num = rentry.num
			lb.decreaseRefCountForReal(raddr)
		} else {
			rentry, found := lb.reals[raddr]
			if found {
				if !slices.Contains(curReals, rentry.num) {
					// increment ref count if it's a new real for this vip
					lb.increaseRefCountForReal(raddr, r.Flags)
					curReals = append(curReals, rentry.num)
				}
				ureal.updatedReal.Num = rentry.num
			} else {
				rnum := lb.increaseRefCountForReal(raddr, r.Flags)
				if rnum == lb.config.maxReals {
					log.Info().Msg("exhausted real's space")
					continue
				}
				ureal.updatedReal.Num = rnum
			}
			ureal.updatedReal.Weight = r.Weight
			ureal.updatedReal.Hash = raddr.hash()
		}
		ureals = append(ureals, ureal)
	}
	chPositions := entry.batchRealsUpdate(ureals)
	vipNum := entry.num
	lb.programHashRing(chPositions, vipNum)
	return true
}

func (lb *FlomeshLb) GetRealsForVip(vip *VipKey) ([]NewReal, error) {
	reals := make([]NewReal, 0)
	if lb.config.disableForwarding {
		log.Error().Msg("getRealsForVip called on non-forwarding instance")
		return reals, nil
	}

	entry, exists := lb.vips[*vip]
	if !exists {
		return nil, fmt.Errorf("trying to get real from non-existing vip: %s", vip.Address)
	}

	vipRealsIds := entry.getRealsAndWeight()
	for _, realId := range vipRealsIds {
		raddr := lb.numToReals[realId.Num]
		nr := NewReal{
			Weight:  realId.Weight,
			Address: string(raddr),
			Flags:   lb.reals[raddr].flags,
		}
		reals = append(reals, nr)
	}
	return reals, nil
}

func (lb *FlomeshLb) GetIndexForReal(real string) int32 {
	if lb.config.disableForwarding {
		log.Error().Msg("getIndexForReal called on non-forwarding instance")
		return -1
	}
	if net.ParseIP(real) != nil {
		raddr := IPAddress(real)
		if entry, exists := lb.reals[raddr]; exists {
			return int32(entry.num)
		}
	}
	return kError
}

func (lb *FlomeshLb) updateVipMap(action ModifyAction, vip *VipKey, meta *bpf.VipMeta) bool {
	vipDef := lb.vipKeyToVipDefinition(vip)
	if action == ADD {
		if err := adapter.BpfUpdateMap(adapter.VipMap, vipDef, meta, ebpf.UpdateAny); err != nil {
			log.Error().Msgf("can't add new element into vip_map, error:%v", err)
			lb.lbStats.bpfFailedCalls++
			return false
		}
		return true
	} else {
		if err := adapter.BpfMapDeleteElement(adapter.VipMap, vipDef); err != nil {
			log.Error().Msgf("can't delete element from vip_map, error:%v", err)
			lb.lbStats.bpfFailedCalls++
			return false
		}
		return true
	}
}

func (lb *FlomeshLb) updateHcKeyMap(action ModifyAction, hcKey *VipKey, hcKeyId uint32) bool {
	vipDef := lb.vipKeyToVipDefinition(hcKey)
	if action == ADD {
		if err := adapter.BpfUpdateMap(adapter.HcKeyMap, vipDef, &hcKeyId, ebpf.UpdateAny); err != nil {
			log.Error().Msgf("can't add new element into hc_key_map, error:%v", err)
			lb.lbStats.bpfFailedCalls++
			return false
		}
		return true
	} else {
		if err := adapter.BpfMapDeleteElement(adapter.HcKeyMap, vipDef); err != nil {
			log.Error().Msgf("can't delete element from hc_key_map, error:%v", err)
			lb.lbStats.bpfFailedCalls++
			return false
		}
		return true
	}
	return true
}

func (lb *FlomeshLb) updateRealsMap(real IPAddress, num uint32, flags uint8) bool {
	addr := net.ParseIP(string(real))
	if addr == nil {
		return false
	}
	realAddr := new(BeAddr)
	realAddr.SetAddr(addr)
	flags &= ^V6DADDR // to keep IPv4/IPv6 specific flag
	realAddr.SetFlags(flags)

	if err := adapter.BpfUpdateMap(adapter.Reals, &num, realAddr, ebpf.UpdateAny); err != nil {
		log.Error().Msgf("can't add new real, error:%v", err)
		lb.lbStats.bpfFailedCalls++
		return false
	}
	return true
}

func (lb *FlomeshLb) vipKeyToVipDefinition(vipKey *VipKey) *bpf.VipDefinition {
	vipAddr := net.ParseIP(vipKey.Address)
	vipDef := new(bpf.VipDefinition)
	if ip4Addr := vipAddr.To4(); ip4Addr != nil {
		vipDef.SetVip4(ip4Addr)
	} else if ip6Addr := vipAddr.To16(); ip6Addr != nil {
		vipDef.SetVip6(ip4Addr)
	}
	vipDef.SetPort(vipKey.Port)
	vipDef.SetProto(vipKey.Proto)
	return vipDef
}

func (lb *FlomeshLb) decreaseRefCountForReal(real IPAddress) {
	entry, exists := lb.reals[real]
	if !exists {
		return
	}
	entry.refCount--
	if entry.refCount == 0 {
		lb.realNums.PushBack(entry.num)
		delete(lb.reals, real)
		delete(lb.numToReals, entry.num)
		if lb.realsIdCallback != nil {
			lb.realsIdCallback.onRealDeleted(real, entry.num)
		}
	}
}

func (lb *FlomeshLb) increaseRefCountForReal(real IPAddress, flags uint8) uint32 {
	entry, exists := lb.reals[real]
	if exists {
		entry.refCount++
		return entry.num
	}

	if lb.realNums.Len() == 0 {
		return lb.config.maxReals
	}

	flags &= ^V6DADDR // to keep IPv4/IPv6 specific flag

	rnum := lb.realNums.PopFront().(uint32)
	lb.numToReals[rnum] = real

	rmeta := new(RealMeta)
	rmeta.refCount = 1
	rmeta.num = rnum
	rmeta.flags = flags
	lb.reals[real] = rmeta

	if !lb.config.testing {
		lb.updateRealsMap(real, rnum, flags)
	}

	if lb.realsIdCallback != nil {
		lb.realsIdCallback.onRealAdded(real, rnum)
	}

	return rnum
}

func (lb *FlomeshLb) GetLruStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kLruCntrOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetLruMissStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kLruMissOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetLruFallbackStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kLruFallbackOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetIcmpTooBigStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kIcmpTooBigOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetQuicRoutingStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kQuicRoutingOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetQuicCidVersionStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kQuicCidVersionOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetQuicCidDropStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kQuicCidDropOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetChDropStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kChDropOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetTcpServerIdRoutingStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kTcpServerIdRoutingOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetSrcRoutingStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kLpmSrcOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetInlineDecapStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kInlineDecapOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetGlobalLruStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kGlobalLruOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetDecapStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kDecapCounterOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetQuicIcmpStats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kQuicIcmpOffset, adapter.Stats)
}

func (lb *FlomeshLb) GetIcmpPtbV6Stats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kIcmpPtbV6Offset, adapter.Stats)
}

func (lb *FlomeshLb) GetIcmpPtbV4Stats() bpf.LbStats {
	return lb.getLbStats(lb.config.maxVips+kIcmpPtbV4Offset, adapter.Stats)
}

func (lb *FlomeshLb) GetRealStats(index uint32) bpf.LbStats {
	return lb.getLbStats(index, adapter.RealsStats)
}

func (lb *FlomeshLb) getLbStats(position uint32, name adapter.BpfMapName) bpf.LbStats {
	if lb.config.disableForwarding {
		return bpf.LbStats{}
	}
	nrCpus, err := adapter.GetPossibleCpus()
	if err != nil {
		return bpf.LbStats{}
	}
	if nrCpus < 1 {
		return bpf.LbStats{}
	}
	stats := make([]bpf.LbStats, nrCpus)
	sumStat := bpf.LbStats{}
	if !lb.config.testing {
		if err := adapter.BpfMapLookupElement(name, &position, stats); err == nil {
			for _, stat := range stats {
				sumStat.V1 += stat.V1
				sumStat.V2 += stat.V1
			}
		} else {
			lb.lbStats.bpfFailedCalls++
		}
	}
	return sumStat
}

func (lb *FlomeshLb) HasFeature(feature FlomeshFeatureEnum) bool {
	switch feature {
	case LocalDeliveryOptimization:
		return lb.features.localDeliveryOptimization
	case DirectHealthchecking:
		return lb.features.directHealthchecking
	case GueEncap:
		return lb.features.gueEncap
	case InlineDecap:
		return lb.features.inlineDecap
	case Introspection:
		return lb.features.introspection
	case SrcRouting:
		return lb.features.srcRouting
	case FlowDebug:
		return lb.features.flowDebug
	default:
		return false
	}
}

func (lb *FlomeshLb) InstallFeature(feature FlomeshFeatureEnum) bool {
	if lb.HasFeature(feature) {
		log.Info().Msgf("already have requested feature:%v", feature)
		return true
	}
	// TODO benne
	return lb.HasFeature(feature)
}

func (lb *FlomeshLb) RemoveFeature(feature FlomeshFeatureEnum) bool {
	if !lb.HasFeature(feature) {
		return true
	}
	// TODO benne
	return !lb.HasFeature(feature)
}

func (lb *FlomeshLb) SetRealsIdCallback(callback RealsIdCallback) {
	lb.realsIdCallback = callback
}

func (lb *FlomeshLb) UnsetRealsIdCallback() {
	lb.realsIdCallback = nil
}
