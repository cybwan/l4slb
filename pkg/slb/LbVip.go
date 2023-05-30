package slb

import (
	"sort"

	"github.com/cybwan/l4slb/pkg/ch"
)

type Vip struct {
	num   uint32
	flags uint32

	chRingSize uint32
	chRing     []int
	chash      ch.ConsistentHash

	reals map[uint32]*VipRealMeta
}

func NewVip(num, flags, ringSize uint32, hfunc ch.HashFunction) *Vip {
	vip := Vip{
		num:        num,
		flags:      flags,
		chRingSize: ringSize,
		chRing:     make([]int, ringSize),
		chash:      ch.Make(hfunc),
		reals:      make(map[uint32]*VipRealMeta),
	}
	for i := uint32(0); i < ringSize; i++ {
		vip.chRing[i] = -1
	}
	return &vip
}

func (v *Vip) GetNum() uint32 {
	return v.num
}

func (v *Vip) GetFlags() uint32 {
	return v.flags
}

func (v *Vip) GetChRingSize() uint32 {
	return v.chRingSize
}

func (v *Vip) SetFlags(flags uint32) {
	v.flags |= flags
}

func (v *Vip) ClearFlags() {
	v.flags = 0
}

func (v *Vip) UnsetFlags(flags uint32) {
	v.flags &= ^flags
}

func (v *Vip) SetHashFunction(hfunc ch.HashFunction) {
	v.chash = ch.Make(hfunc)
}

func (v *Vip) calculateHashRing(endpoints []ch.Endpoint) []RealPos {
	delta := make([]RealPos, 0)
	if len(endpoints) > 0 {
		newChRing := v.chash.GenerateHashRing(endpoints, v.chRingSize)
		// compare new and old ch rings. send back only delta between em.
		for i := uint32(0); i < v.chRingSize; i++ {
			if newChRing[i] != v.chRing[i] {
				newPos := RealPos{
					pos:  i,
					real: uint32(newChRing[i]),
				}
				delta = append(delta, newPos)
				v.chRing[i] = newChRing[i]
			}
		}
	}
	return delta
}

func (v *Vip) batchRealsUpdate(ureals []UpdateReal) []RealPos {
	endpoints := v.getEndpoints(ureals)
	return v.calculateHashRing(endpoints)
}

func (v *Vip) recalculateHashRing() []RealPos {
	reals := v.getRealsAndWeight()
	return v.calculateHashRing(reals)
}

func (v *Vip) addReal(real ch.Endpoint) []RealPos {
	ureal := UpdateReal{
		action:      ADD,
		updatedReal: real,
	}
	reals := []UpdateReal{ureal}
	return v.batchRealsUpdate(reals)
}

func (v *Vip) delReal(realNum uint32) []RealPos {
	ureal := UpdateReal{
		action: DEL,
		updatedReal: ch.Endpoint{
			Num: realNum,
		},
	}
	reals := []UpdateReal{ureal}
	return v.batchRealsUpdate(reals)
}

func (v *Vip) getReals() []uint32 {
	realNums := make([]uint32, 0)
	for k := range v.reals {
		realNums = append(realNums, k)
	}
	return realNums
}

func (v *Vip) getRealsAndWeight() []ch.Endpoint {
	endpoints := make(ch.EndpointSlice, len(v.reals))
	i := 0
	for n, r := range v.reals {
		endpoint := ch.Endpoint{
			Num:    n,
			Weight: r.weight,
			Hash:   r.hash,
		}
		endpoints[i] = endpoint
		i++
	}
	sort.Sort(endpoints)
	return endpoints
}

func (v *Vip) getEndpoints(ureals []UpdateReal) []ch.Endpoint {
	endpoints := make(ch.EndpointSlice, 0)
	realsChanged := false
	for _, ureal := range ureals {
		if ureal.action == DEL {
			delete(v.reals, ureal.updatedReal.Num)
			realsChanged = true
		} else {
			realMeta, exists := v.reals[ureal.updatedReal.Num]
			if !exists {
				realMeta = new(VipRealMeta)
				v.reals[ureal.updatedReal.Num] = realMeta
			}
			curWeight := realMeta.weight
			if curWeight != ureal.updatedReal.Weight {
				realMeta.weight = ureal.updatedReal.Weight
				realMeta.hash = ureal.updatedReal.Hash
				realsChanged = true
			}
		}
	}
	if realsChanged {
		for n, r := range v.reals {
			if r.weight != 0 {
				endpoint := ch.Endpoint{
					Num:    n,
					Weight: r.weight,
					Hash:   r.hash,
				}
				endpoints = append(endpoints, endpoint)
			}
		}
		sort.Sort(endpoints)
	}
	return endpoints
}
