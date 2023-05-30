package bpf

import (
	"encoding/binary"
	"github.com/cybwan/l4slb/pkg/bpf/progs/balancer"
	"github.com/cybwan/l4slb/pkg/bpf/progs/healthchecking/ipip"
	"github.com/cybwan/l4slb/pkg/bpf/progs/healthchecking/kern"
	"github.com/cybwan/l4slb/pkg/endian"
	"net"
)

type CtlValue struct {
	//balancer.CtlValue_
	val [8]uint8
}

func (v *CtlValue) SetValue(value uint64) {
	binary.LittleEndian.PutUint64(v.val[:], value)
}

func (v *CtlValue) SetIfIndex(ifIndex uint32) {
	binary.BigEndian.PutUint32(v.val[:], ifIndex)
}

func (v *CtlValue) GetIfIndex() uint32 {
	return binary.BigEndian.Uint32(v.val[:])
}

func (v *CtlValue) SetMac(mac []uint8) {
	copy(v.val[:], mac)
}

func (v *CtlValue) GetMac() []uint8 {
	return v.val[0:6]
}

type FlowKey struct {
	balancer.FlowKey_
}

type LbStats struct {
	balancer.LbStats_
}

type RealDefinition struct {
	balancer.RealDefinition_
}

type RealPosLru struct {
	balancer.RealPosLru_
}

type V4LpmKey struct {
	balancer.V4LpmKey_
}

type V6LpmKey struct {
	balancer.V6LpmKey_
}

type VipDefinition struct {
	//balancer.VipDefinition_
	vip   [16]byte
	port  uint16
	proto uint8
	_     [1]byte
}

func (v *VipDefinition) SetVip4(ipaddr net.IP) {
	copy(v.vip[:], ipaddr.To4())
}

func (v *VipDefinition) SetVip6(ipaddr net.IP) {
	copy(v.vip[:], ipaddr.To16())
}

func (v *VipDefinition) SetPort(port uint16) {
	v.port = endian.BigEndian16(port)
}

func (v *VipDefinition) SetProto(proto uint8) {
	v.proto = proto
}

type VipMeta struct {
	balancer.VipMeta_
}

type HcRealDefinition struct {
	ipip.HcRealDefinition_
	//kern.HcRealDefinition_
}

type HcStats struct {
	ipip.HcStats_
	//kern.HcStats_
}

type HcKey struct {
	kern.HcKey_
}

type HcMac struct {
	//kern.HcMac_
	mac [6]uint8
}

func (v *HcMac) SetMac(mac []uint8) {
	copy(v.mac[:], mac)
}
