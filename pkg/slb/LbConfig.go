package slb

import "github.com/cybwan/l4slb/pkg/ch"

// TODO benne
type FlomeshLbMonitorConfig struct {
	nCpus      uint32
	pages      uint32
	mapFd      int
	queueSize  uint32
	pcktLimit  uint32
	snapLen    uint32
	storage    PcapStorageFormat
	bufferSize uint32
}

type FlomeshLbConfig struct {
	mainInterface          string
	v4TunInterface         string
	v6TunInterface         string
	balancerProgPath       string
	healthcheckingProgPath string
	defaultMac             []uint8
	priority               uint32
	rootMapPath            string
	rootMapPos             uint32
	enableHc               bool
	tunnelBasedHCEncap     bool
	disableForwarding      bool
	maxVips                uint32
	maxReals               uint32
	chRingSize             uint32
	testing                bool
	LruSize                uint64
	forwardingCores        []int32
	numaNodes              []int32
	maxLpmSrcSize          uint32
	maxDecapDst            uint32
	hcInterface            string
	xdpAttachFlags         uint32
	monitorConfig          FlomeshLbMonitorConfig
	memlockUnlimited       bool
	LbSrcV4                string
	LbSrcV6                string
	localMac               []uint8
	hashFunction           ch.HashFunction
	flowDebug              bool
	globalLruSize          uint32
	useRootMap             bool
}

func NewFlomeshLbConfig() *FlomeshLbConfig {
	return &FlomeshLbConfig{
		v4TunInterface:     kDefaultHcInterface,
		v6TunInterface:     kDefaultHcInterface,
		rootMapPath:        kNoExternalMap,
		rootMapPos:         kDefaultFlomeshLbPos,
		enableHc:           true,
		tunnelBasedHCEncap: true,
		maxVips:            kDefaultMaxVips,
		maxReals:           kDefaultMaxReals,
		chRingSize:         kLbDefaultChRingSize,
		LruSize:            kDefaultLruSize,
		maxLpmSrcSize:      kDefaultMaxLpmSrcSize,
		maxDecapDst:        kDefaultMaxDecapDstSize,
		hcInterface:        kDefaultHcInterface,
		xdpAttachFlags:     kNoFlags,
		memlockUnlimited:   true,
		LbSrcV4:            kAddressNotSpecified,
		LbSrcV6:            kAddressNotSpecified,
		hashFunction:       ch.Maglev,
		globalLruSize:      kDefaultGlobalLruSize,
		useRootMap:         true,
	}
}
