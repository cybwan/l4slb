package cli

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/cybwan/l4slb/pkg/logger"
	"github.com/cybwan/l4slb/pkg/pb"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	NO_SPORT    = 1
	NO_LRU      = 2
	QUIC_VIP    = 4
	DPORT_HASH  = 8
	LOCAL_VIP   = 32

	LOCAL_REAL = 2
)

const (
	ADD_VIP = iota
	DEL_VIP
	MODIFY_VIP
)

var (
	log = logger.New("l4slb-cli")

	vipFlagTranslationTable = map[string]int32{
		"NO_SPORT":   NO_SPORT,
		"NO_LRU":     NO_LRU,
		"QUIC_VIP":   QUIC_VIP,
		"DPORT_HASH": DPORT_HASH,
		"LOCAL_VIP":  LOCAL_VIP,
	}
	realFlagTranslationTable = map[string]int32{
		"LOCAL_REAL": LOCAL_REAL,
	}
)

func checkError(err error) {
	if err != nil {
		log.Fatal().Msgf("Error: %v", err)
	}
}

type L4SlbClient struct {
	client pb.SlbServiceClient
}

func (kc *L4SlbClient) Init(serverAddr string) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		log.Fatal().Msgf("Can't connect to local flomesh lb server! err is %v", err)
	}
	kc.client = pb.NewSlbServiceClient(conn)
}

func (kc *L4SlbClient) ChangeMac(mac string) {
	newMac := pb.Mac{Mac: mac}
	res, err := kc.client.ChangeMac(context.Background(), &newMac)
	checkError(err)
	if res.Success == true {
		log.Print("Mac address changed!")
	} else {
		log.Print("Mac was not changed")
	}
}

func (kc *L4SlbClient) GetMac() {
	mac, err := kc.client.GetMac(context.Background(), &pb.Empty{})
	checkError(err)
	log.Info().Msgf("Mac address is %v", mac.GetMac())
}

func parseToVip(addr string, proto int) pb.Vip {
	var vip pb.Vip
	vip.Protocol = int32(proto)
	if strings.Index(addr, "[") >= 0 {
		// v6 address. format [<addr>]:<port>
		v6re := regexp.MustCompile(`\[(.*?)\]:(.*)`)
		addr_port := v6re.FindStringSubmatch(addr)
		if addr_port == nil {
			log.Fatal().Msgf("invalid v6 address %v", addr)
		}
		vip.Address = addr_port[1]
		port, err := strconv.ParseInt(addr_port[2], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	} else {
		// v4 address. format <addr>:<port>
		addr_port := strings.Split(addr, ":")
		if len(addr_port) != 2 {
			log.Fatal().Msgf("incorrect v4 address: %v", addr)
		}
		vip.Address = addr_port[0]
		port, err := strconv.ParseInt(addr_port[1], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	}
	return vip
}

func parseToReal(addr string, weight int64, flags int32) pb.Real {
	var real pb.Real
	real.Address = addr
	real.Weight = int32(weight)
	real.Flags = flags
	return real
}

func parseToQuicReal(mapping string) pb.QuicReal {
	addr_id := strings.Split(mapping, "=")
	if len(addr_id) != 2 {
		panic("quic mapping must be in <addr>=<id> format")
	}
	id, err := strconv.ParseInt(addr_id[1], 10, 64)
	checkError(err)
	var qr pb.QuicReal
	qr.Address = addr_id[0]
	qr.Id = int32(id)
	return qr
}

func (kc *L4SlbClient) AddOrModifyService(
	addr string, flagsString string, proto int, modify bool, setFlags bool) {
	log.Info().Msgf("Adding service: %v %v", addr, proto)
	vip := parseToVip(addr, proto)
	var flags int32
	var exists bool
	if flagsString != "" {
		if flags, exists = vipFlagTranslationTable[flagsString]; !exists {
			log.Info().Msgf("unrecognized flag: %v", flagsString)
			return
		}
	}
	if modify {
		kc.UpdateService(vip, flags, MODIFY_VIP, setFlags)
	} else {
		kc.UpdateService(vip, flags, ADD_VIP, setFlags)
	}
}

func (kc *L4SlbClient) DelService(addr string, proto int) {
	log.Info().Msgf("Deleting service: %v %v", addr, proto)
	vip := parseToVip(addr, proto)
	kc.UpdateService(vip, 0, DEL_VIP, false)
}

func (kc *L4SlbClient) UpdateReal(addr string, flags int32, setFlags bool) {
	var rMeta pb.RealMeta
	rMeta.Address = addr
	rMeta.Flags = flags
	rMeta.SetFlag = setFlags
	ok, err := kc.client.ModifyReal(context.Background(), &rMeta)
	checkError(err)
	if ok.Success {
		log.Info().Msgf("Real modified")
	}
}

func (kc *L4SlbClient) UpdateService(
	vip pb.Vip, flags int32, action int, setFlags bool) {
	var vMeta pb.VipMeta
	var ok *pb.Bool
	var err error
	vMeta.Vip = &vip
	vMeta.Flags = flags
	vMeta.SetFlag = setFlags
	switch action {
	case MODIFY_VIP:
		ok, err = kc.client.ModifyVip(context.Background(), &vMeta)
		break
	case ADD_VIP:
		ok, err = kc.client.AddVip(context.Background(), &vMeta)
		break
	case DEL_VIP:
		ok, err = kc.client.DelVip(context.Background(), &vip)
		break
	default:
		break
	}
	checkError(err)
	if ok.Success {
		log.Info().Msgf("Vip modified")
	}
}

func (kc *L4SlbClient) UpdateServerForVip(
	vipAddr string, proto int, realAddr string, weight int64, realFlags string, delete bool) {
	vip := parseToVip(vipAddr, proto)
	var flags int32
	var exists bool
	if realFlags != "" {
		if flags, exists = realFlagTranslationTable[realFlags]; !exists {
			log.Info().Msgf("unrecognized flag: %v", realFlags)
			return
		}
	}
	real := parseToReal(realAddr, weight, flags)
	var action pb.Action
	if delete {
		action = pb.Action_DEL
	} else {
		action = pb.Action_ADD
	}
	var reals pb.Reals
	reals.Reals = append(reals.Reals, &real)
	kc.ModifyRealsForVip(&vip, &reals, action)
}

func (kc *L4SlbClient) ModifyRealsForVip(
	vip *pb.Vip, reals *pb.Reals, action pb.Action) {
	var mReals pb.ModifiedRealsForVip
	mReals.Vip = vip
	mReals.Real = reals
	mReals.Action = action
	ok, err := kc.client.ModifyRealsForVip(context.Background(), &mReals)
	checkError(err)
	if ok.Success {
		log.Info().Msgf("Reals modified")
	}
}

func (kc *L4SlbClient) ModifyQuicMappings(mapping string, delete bool) {
	var action pb.Action
	if delete {
		action = pb.Action_DEL
	} else {
		action = pb.Action_ADD
	}
	qr := parseToQuicReal(mapping)
	var qrs pb.QuicReals
	qrs.Qreals = append(qrs.Qreals, &qr)
	var mqr pb.ModifiedQuicReals
	mqr.Reals = &qrs
	mqr.Action = action
	ok, err := kc.client.ModifyQuicRealsMapping(
		context.Background(), &mqr)
	checkError(err)
	if ok.Success {
		log.Info().Msgf("Quic mapping modified")
	}
}

func (kc *L4SlbClient) GetAllVips() pb.Vips {
	vips, err := kc.client.GetAllVips(context.Background(), &pb.Empty{})
	checkError(err)
	return *vips
}

func (kc *L4SlbClient) GetAllHcs() pb.HcMap {
	hcs, err := kc.client.GetHealthcheckersDst(
		context.Background(), &pb.Empty{})
	checkError(err)
	return *hcs
}

func (kc *L4SlbClient) GetRealsForVip(vip *pb.Vip) pb.Reals {
	reals, err := kc.client.GetRealsForVip(context.Background(), vip)
	checkError(err)
	return *reals
}

func (kc *L4SlbClient) GetVipFlags(vip *pb.Vip) uint64 {
	flags, err := kc.client.GetVipFlags(context.Background(), vip)
	checkError(err)
	return flags.Flags
}

func parseVipFlags(flags uint64) string {
	flags_str := ""
	if flags&uint64(NO_SPORT) > 0 {
		flags_str += " NO_SPORT "
	}
	if flags&uint64(NO_LRU) > 0 {
		flags_str += " NO_LRU "
	}
	if flags&uint64(QUIC_VIP) > 0 {
		flags_str += " QUIC_VIP "
	}
	if flags&uint64(DPORT_HASH) > 0 {
		flags_str += " DPORT_HASH "
	}
	if flags&uint64(LOCAL_VIP) > 0 {
		flags_str += " LOCAL_VIP "
	}
	return flags_str
}

func parseRealFlags(flags int32) string {
	if flags < 0 {
		log.Fatal().Msgf("invalid real flags passed: %v", flags)
	}
	flags_str := ""
	if flags&LOCAL_REAL > 0 {
		flags_str += " LOCAL_REAL "
	}
	return flags_str
}

func (kc *L4SlbClient) ListVipAndReals(vip *pb.Vip) {
	reals := kc.GetRealsForVip(vip)
	proto := ""
	if vip.Protocol == IPPROTO_TCP {
		proto = "tcp"
	} else {
		proto = "udp"
	}
	log.Info().Msgf("VIP: %20v Port: %6v Protocol: %v",
		vip.Address,
		vip.Port,
		proto)
	flags := kc.GetVipFlags(vip)
	log.Info().Msgf("Vip's flags: %v", parseVipFlags(flags))
	for _, real := range reals.Reals {
		log.Info().Msgf("%-20v weight: %v flags: %v",
			" ->"+real.Address,
			real.Weight, parseRealFlags(real.Flags))
	}
}

func (kc *L4SlbClient) List(addr string, proto int) {
	vips := kc.GetAllVips()
	log.Info().Msgf("vips len %v", len(vips.Vips))
	for _, vip := range vips.Vips {
		kc.ListVipAndReals(vip)
	}
}

func (kc *L4SlbClient) ClearAll() {
	log.Info().Msgf("Deleting Vips")
	vips := kc.GetAllVips()
	for _, vip := range vips.Vips {
		ok, err := kc.client.DelVip(context.Background(), vip)
		if err != nil || !ok.Success {
			log.Info().Msgf("error while deleting vip: %v", vip.Address)
		}
	}
	log.Info().Msgf("Deleting Healthchecks")
	hcs := kc.GetAllHcs()
	var Somark pb.Somark
	for somark, _ := range hcs.Healthchecks {
		Somark.Somark = uint32(somark)
		ok, err := kc.client.DelHealthcheckerDst(context.Background(), &Somark)
		if err != nil || !ok.Success {
			log.Info().Msgf("error while deleting hc w/ somark: %v", somark)
		}
	}
}

func (kc *L4SlbClient) ListQm() {
	log.Info().Msgf("printing address to quic's connection id mapping")
	qreals, err := kc.client.GetQuicRealsMapping(
		context.Background(), &pb.Empty{})
	checkError(err)
	for _, qr := range qreals.Qreals {
		log.Info().Msgf("real: %20v = connection id: %6v",
			qr.Address,
			qr.Id)
	}
}

func (kc *L4SlbClient) AddHc(addr string, somark uint64) {
	var hc pb.Healthcheck
	hc.Somark = uint32(somark)
	hc.Address = addr
	ok, err := kc.client.AddHealthcheckerDst(context.Background(), &hc)
	checkError(err)
	if !ok.Success {
		log.Info().Msgf("error while add hc w/ somark: %v and addr %v", somark, addr)
	}
}

func (kc *L4SlbClient) DelHc(somark uint64) {
	var sm pb.Somark
	sm.Somark = uint32(somark)
	ok, err := kc.client.DelHealthcheckerDst(context.Background(), &sm)
	checkError(err)
	if !ok.Success {
		log.Info().Msgf("error while deleting hc w/ somark: %v", somark)
	}
}

func (kc *L4SlbClient) ListHc() {
	hcs := kc.GetAllHcs()
	for somark, addr := range hcs.Healthchecks {
		log.Info().Msgf("somark: %10v addr: %10v",
			somark,
			addr)
	}
}

func (kc *L4SlbClient) ShowSumStats() {
	oldPkts := uint64(0)
	oldBytes := uint64(0)
	vips := kc.GetAllVips()
	for true {
		pkts := uint64(0)
		bytes := uint64(0)
		for _, vip := range vips.Vips {
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			pkts += stats.V1
			bytes += stats.V2
		}
		diffPkts := pkts - oldPkts
		diffBytes := bytes - oldBytes
		log.Info().Msgf("summary: %v pkts/sec %v bytes/sec", diffPkts, diffBytes)
		oldPkts = pkts
		oldBytes = bytes
		time.Sleep(1 * time.Second)
	}
}

func (kc *L4SlbClient) ShowLruStats() {
	oldTotalPkts := uint64(0)
	oldMiss := uint64(0)
	oldTcpMiss := uint64(0)
	oldTcpNonSynMiss := uint64(0)
	oldFallbackLru := uint64(0)
	for true {
		lruMiss := float64(0)
		tcpMiss := float64(0)
		tcpNonSynMiss := float64(0)
		udpMiss := float64(0)
		lruHit := float64(0)
		stats, err := kc.client.GetLruStats(
			context.Background(), &pb.Empty{})
		if err != nil {
			continue
		}
		missStats, err := kc.client.GetLruMissStats(
			context.Background(), &pb.Empty{})
		if err != nil {
			continue
		}
		fallbackStats, err := kc.client.GetLruFallbackStats(
			context.Background(), &pb.Empty{})
		if err != nil {
			continue
		}
		diffTotal := stats.V1 - oldTotalPkts
		diffMiss := stats.V2 - oldMiss
		diffTcpMiss := missStats.V1 - oldTcpMiss
		diffTcpNonSynMiss := missStats.V2 - oldTcpNonSynMiss
		diffFallbackLru := fallbackStats.V1 - oldFallbackLru
		if diffTotal != 0 {
			lruMiss = float64(diffMiss) / float64(diffTotal)
			tcpMiss = float64(diffTcpMiss) / float64(diffTotal)
			tcpNonSynMiss = float64(diffTcpNonSynMiss) / float64(diffTotal)
			udpMiss = 1 - (tcpMiss + tcpNonSynMiss)
			lruHit = 1 - lruMiss
		}
		log.Info().Msgf("summary: %d pkts/sec. lru hit: %.2f%% lru miss: %.2f%% ",
			diffTotal, lruHit*100, lruMiss*100)
		log.Info().Msgf("(tcp syn: %.2f%% tcp non-syn: %.2f%% udp: %.2f%%)", tcpMiss,
			tcpNonSynMiss, udpMiss)
		log.Info().Msgf(" fallback lru hit: %d pkts/sec", diffFallbackLru)
		oldTotalPkts = stats.V1
		oldMiss = stats.V2
		oldTcpMiss = missStats.V1
		oldTcpNonSynMiss = missStats.V2
		oldFallbackLru = fallbackStats.V1
		time.Sleep(1 * time.Second)
	}
}

func (kc *L4SlbClient) ShowPerVipStats() {
	vips := kc.GetAllVips()
	statsMap := make(map[string]uint64)
	for _, vip := range vips.Vips {
		key := strings.Join([]string{
			vip.Address, strconv.Itoa(int(vip.Port)),
			strconv.Itoa(int(vip.Protocol))}, ":")
		statsMap[key+":pkts"] = 0
		statsMap[key+":bytes"] = 0
	}
	for true {
		for _, vip := range vips.Vips {
			key := strings.Join([]string{
				vip.Address, strconv.Itoa(int(vip.Port)),
				strconv.Itoa(int(vip.Protocol))}, ":")
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			diffPkts := stats.V1 - statsMap[key+":pkts"]
			diffBytes := stats.V2 - statsMap[key+":bytes"]
			log.Info().Msgf("vip: %16s : %8d pkts/sec %8d bytes/sec",
				key, diffPkts, diffBytes)
			statsMap[key+":pkts"] = stats.V1
			statsMap[key+":bytes"] = stats.V2
		}
		time.Sleep(1 * time.Second)
	}
}

func (kc *L4SlbClient) ShowIcmpStats() {
	oldIcmpV4 := uint64(0)
	oldIcmpV6 := uint64(0)
	for true {
		icmps, err := kc.client.GetIcmpTooBigStats(
			context.Background(), &pb.Empty{})
		checkError(err)
		diffIcmpV4 := icmps.V1 - oldIcmpV4
		diffIcmpV6 := icmps.V2 - oldIcmpV6
		log.Info().Msgf(
			"ICMP \"packet too big\": v4 %v pkts/sec v6: %v pkts/sec",
			diffIcmpV4, diffIcmpV6)
		oldIcmpV4 = icmps.V1
		oldIcmpV6 = icmps.V2
		time.Sleep(1 * time.Second)
	}
}
