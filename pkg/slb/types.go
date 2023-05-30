package slb

import (
	"github.com/cybwan/l4slb/pkg/bpf"
	"github.com/cybwan/l4slb/pkg/ch"
	"github.com/cybwan/l4slb/pkg/logger"
	"github.com/cybwan/l4slb/pkg/stack"
	"go.eth-p.dev/goptional"
	"hash/fnv"
	"net"
)

const (
	kDefaultPriority         uint32 = 2307
	kDefaultFlomeshLbPos     uint32 = 2
	kDefaultMaxVips          uint32 = 512
	kDefaultMaxReals         uint32 = 4096
	kLbDefaultChRingSize     uint32 = 65537
	kDefaultMaxLpmSrcSize    uint32 = 3000000
	kDefaultMaxDecapDstSize  uint32 = 6
	kDefaultNumOfPages       uint32 = 2
	kDefaultMonitorQueueSize uint32 = 4096
	kDefaultMonitorPcktLimit uint32 = 0
	kDefaultMonitorSnapLen   uint32 = 128
	kDefaultGlobalLruSize    uint32 = 100000
	kNoFlags                 uint32 = 0
	kDefaultLruSize          uint64 = 8000000

	kNoExternalMap       = ""
	kDefaultHcInterface  = ""
	kAddressNotSpecified = ""
)

// RealMeta meta info for real
type RealMeta struct {
	// vip's number
	num uint32

	/**
	 * one real could be used by multiple vips
	 * we will delete real (recycle it's num),
	 * only when refcount would be equal to zero
	 */
	refCount uint32
	flags    uint8
}

// NewReal information about new real
type NewReal struct {
	Address string
	Weight  uint32
	Flags   uint8
}

// QuicReal information about quic's real
type QuicReal struct {
	Address string
	Id      uint32
}

type PcapStorageFormat int

const (
	FILE PcapStorageFormat = iota
	IOBUF
	PIPE
)

type ModifyAction int8

type AddressType int

const (
	INVALID AddressType = iota
	HOST
	NETWORK
)

type IPAddress string

func (addr *IPAddress) hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte(*addr))
	return h.Sum64()
}

type CIDRNetwork string

func (cidr *CIDRNetwork) hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte(*cidr))
	return h.Sum64()
}

const (
	ADD ModifyAction = iota
	DEL
)

type VipKey struct {
	Address string
	Port    uint16
	Proto   uint8
}

func (v *VipKey) Equals(o *VipKey) bool {
	return v.Address == o.Address && v.Port == o.Port && v.Proto == o.Proto
}

// VipRealMeta is used by Vip class to store real's related metadata such as real's weight and hash
type VipRealMeta struct {
	weight uint32
	hash   uint64
}

// RealPos show on which position real w/ specified opaque id should be located on ch ring.
type RealPos struct {
	real uint32
	pos  uint32
}

type UpdateReal struct {
	action      ModifyAction
	updatedReal ch.Endpoint
}

type BeAddr struct {
	addr  [16]byte
	flags uint8
	_     [3]byte
}

func (v *BeAddr) SetAddr(addr net.IP) {
	if ip := addr.To4(); ip != nil {
		v.SetV4Addr(ip)
	} else if ip = addr.To16(); ip != nil {
		v.SetV6Addr(ip)
		v.flags = V6DADDR
	}
}

func (v *BeAddr) SetV4Addr(ipaddr net.IP) {
	copy(v.addr[:], ipaddr.To4())
}

func (v *BeAddr) SetV6Addr(ipaddr net.IP) {
	copy(v.addr[:], ipaddr.To16())
}

func (v *BeAddr) SetFlags(flags uint8) {
	v.flags = flags
}

type RealsIdCallback interface {
	onRealAdded(real IPAddress, id uint32)
	onRealDeleted(real IPAddress, id uint32)
}

type FlomeshLb struct {
	config *FlomeshLbConfig

	vipNums   stack.Stack
	realNums  stack.Stack
	hcKeyNums stack.Stack

	//vector of control elements (such as default's mac; ifindexes etc)
	ctlValues []bpf.CtlValue

	//dict of so_mark to real mapping; for healthchecking
	hcReals map[uint32]IPAddress

	reals map[IPAddress]*RealMeta

	/**
	 * key: QUIC host id (from CID); value: real IP
	 */
	quicMapping map[uint32]IPAddress

	/**
	 * for reverse real's lookup. get real by num.
	 * used when we are going to delete vip and coresponding reals.
	 */
	numToReals map[uint32]IPAddress

	vips map[VipKey]*Vip

	lruMissStatsVip goptional.Optional[VipKey]

	//Maps an HcKey to its id
	hckeys map[VipKey]uint32

	//map of src address to dst mapping. used for source based routing.
	lpmSrcMapping map[CIDRNetwork]uint32

	//flag which indicates if working in "standalone" mode or not.
	standalone bool

	// flag which indicates that bpf progs has been loaded.
	progsLoaded bool

	//flag which indicates that bpf progs has been attached
	progsAttached bool

	//enabled optional features
	features FlomeshLbFeatures

	/**
	 * vector of forwarding CPUs (cpus/cores which are responisible for NICs
	 * irq handling)
	 */
	forwardingCores []int32

	/**
	 * optional vector, which contains mapping of forwarding cores to NUMA numa
	 * length of this vector must be either zero (in this case we don't use it)
	 * or equal to the length of forwardingCores_
	 */
	numaNodes []int32

	//userspace library stats
	lbStats FlomeshLbStats

	//flag which indicates that introspection routines already started
	introspectionStarted_ bool

	//flag which indicates that bpf program was reloaded
	progsReloaded bool

	//Callback to be notified when a real is added or deleted
	realsIdCallback RealsIdCallback
}

type FlomeshLbMonitorStats struct {
	limit      uint32
	amount     uint32
	bufferFull uint32
}

type FlomeshLbBpfMapStats struct {
	maxEntries     uint32
	currentEntries uint32
}

type FlomeshLbStats struct {
	bpfFailedCalls       uint64
	addrValidationFailed uint64
}

type HealthCheckProgStats struct {
	packetsProcessed uint64
	packetsDropped   uint64
	packetsSkipped   uint64
	packetsTooBig    uint64
}

type FlomeshLbFeatures struct {
	srcRouting                bool
	inlineDecap               bool
	introspection             bool
	gueEncap                  bool
	directHealthchecking      bool
	localDeliveryOptimization bool
	flowDebug                 bool
}

type FlomeshFeatureEnum uint8

const (
	SrcRouting                FlomeshFeatureEnum = 1 << 0
	InlineDecap               FlomeshFeatureEnum = 1 << 1
	Introspection             FlomeshFeatureEnum = 1 << 2
	GueEncap                  FlomeshFeatureEnum = 1 << 3
	DirectHealthchecking      FlomeshFeatureEnum = 1 << 4
	LocalDeliveryOptimization FlomeshFeatureEnum = 1 << 5
	FlowDebug                 FlomeshFeatureEnum = 1 << 6
)

var (
	log = logger.New("slb")
)
