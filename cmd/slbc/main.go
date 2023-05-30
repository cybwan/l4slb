package main

import (
	"flag"
	"fmt"

	"github.com/cybwan/l4slb/pkg/cli"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

var (
	addService  = flag.Bool("A", false, "Add new virtual service")
	editService = flag.Bool("E", false, "Edit existing virtual service")
	delService  = flag.Bool("D", false, "Delete existing virtual service")
	addServer   = flag.Bool("a", false, "Add real server")
	editServer  = flag.Bool("e", false, "Edit real server")
	delServer   = flag.Bool("d", false, "Delete real server")
	tcpService  = flag.String("t", "",
		"Tcp service address. must be in format: <addr>:<port>")
	udpService = flag.String("u", "",
		"Udp service addr. must be in format: <addr>:<port>")
	realServer     = flag.String("r", "", "Address of the real server")
	realWeight     = flag.Int64("w", 1, "Weight (capacity) of real server")
	showStats      = flag.Bool("s", false, "Show stats/counters")
	showSumStats   = flag.Bool("sum", false, "Show summary stats")
	showLruStats   = flag.Bool("lru", false, "Show LRU related stats")
	showIcmpStats  = flag.Bool("icmp", false, "Show ICMP 'packet too big' related stats")
	listServices   = flag.Bool("l", false, "List configured services")
	vipChangeFlags = flag.String("vf", "",
		"change vip flags. Possible values: NO_SPORT, NO_LRU, QUIC_VIP, DPORT_HASH, LOCAL_VIP")
	realChangeFlags = flag.String("rf", "",
		"change real flags. Possible values: LOCAL_REAL")
	unsetFlags = flag.Bool("unset", false, "Unset specified flags")
	newHc      = flag.String("new_hc", "", "Address of new backend to healtcheck")
	somark     = flag.Uint64("somark", 0, "Socket mark to specified backend")
	delHc      = flag.Bool("del_hc", false, "Delete backend w/ specified somark")
	listHc     = flag.Bool("list_hc", false, "List configured healthchecks")
	listMac    = flag.Bool("list_mac", false,
		"List configured mac address of default router")
	changeMac = flag.String("change_mac", "",
		"Change configured mac address of default router")
	clearAll    = flag.Bool("C", false, "Clear all configs")
	quicMapping = flag.String("quic_mapping", "",
		"mapping of real to connectionId. must be in <addr>=<id> format")
	listQuicMapping = flag.Bool("list_qm", false, "List current quic's mappings")
	delQuicMapping  = flag.Bool("del_qm", false,
		"Delete instead of adding specified quic mapping")
	slbServer = flag.String("server", "127.0.0.1:50051",
		"Flomesh lb server listen address")
)

func main() {
	flag.Parse()
	var service string
	var proto int
	if *tcpService != "" {
		service = *tcpService
		proto = IPPROTO_TCP
	} else if *udpService != "" {
		service = *udpService
		proto = IPPROTO_UDP
	}
	var sc cli.L4SlbClient
	sc.Init(*slbServer)
	if *changeMac != "" {
		sc.ChangeMac(*changeMac)
	} else if *listMac {
		sc.GetMac()
	} else if *addService {
		sc.AddOrModifyService(service, *vipChangeFlags, proto, false, true)
	} else if *listServices {
		// TODO(tehnerd): print only specified tcp/udp service
		sc.List("", 0)
	} else if *delService {
		sc.DelService(service, proto)
	} else if *editService {
		sc.AddOrModifyService(service, *vipChangeFlags, proto, true, !*unsetFlags)
	} else if *addServer || *editServer {
		sc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, false)
	} else if *delServer {
		sc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, true)
	} else if *delQuicMapping {
		sc.ModifyQuicMappings(*quicMapping, true)
	} else if *quicMapping != "" {
		sc.ModifyQuicMappings(*quicMapping, false)
	} else if *listQuicMapping {
		sc.ListQm()
	} else if *clearAll {
		sc.ClearAll()
	} else if *newHc != "" {
		sc.AddHc(*newHc, *somark)
	} else if *delHc {
		sc.DelHc(*somark)
	} else if *listHc {
		sc.ListHc()
	} else if *showStats {
		if *showSumStats {
			sc.ShowSumStats()
		} else if *showLruStats {
			sc.ShowLruStats()
		} else if *showIcmpStats {
			sc.ShowIcmpStats()
		} else {
			sc.ShowPerVipStats()
		}
	}
	fmt.Printf("exiting\n")
}
