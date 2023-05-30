package adapter

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
	"time"
)

const (
	GET_DEFAULT_IP_ADDRESS string = "route show default"
	PING_CMD               string = "-c 1 -q -w 1 "
	MAC_CMD                string = "neighbor show "
)

func getCmdOutput(binary_name string, args string) string {
	var out bytes.Buffer
	args_slice := strings.Fields(args)
	cmd := exec.Command(binary_name, args_slice...)
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("error while running %s w/ args %s: %v\n",
			cmd, args, err)
		return ""
	}
	return out.String()

}

func getDefaultGatewayIp() string {
	ip_line := getCmdOutput("ip", GET_DEFAULT_IP_ADDRESS)
	if len(ip_line) == 0 {
		return ip_line
	}
	ip_line_slice := strings.Fields(ip_line)
	// we are expecting for ip line to looks like something like
	// default via 10.0.2.2 dev enp0s3 proto dhcp src 10.0.2.15 metric 100
	if len(ip_line_slice) < 3 {
		return ""
	}
	return ip_line_slice[2]
}

func pingIp(ip string) {
	args := PING_CMD + ip
	getCmdOutput("ping", args)
}

func getDefaultMac(ip string) string {
	args := MAC_CMD + ip
	out := getCmdOutput("ip", args)
	if len(out) == 0 {
		return out
	}
	out_slice := strings.Fields(out)
	// expecing to see something like
	// 10.0.2.2 dev enp0s3 lladdr 52:54:00:12:35:02 REACHABLE
	if len(out_slice) < 5 {
		return ""
	}
	return out_slice[4]
}

func GetDefaultGatewayMac() string {
	ip := getDefaultGatewayIp()
	pingIp(ip)
	return getDefaultMac(ip)
}

func CheckDefaultGwMac(changeMac func(mac string), mac string) {
	current_mac := mac
	for {
		new_mac := GetDefaultGatewayMac()
		if len(new_mac) > 0 && current_mac != new_mac {
			changeMac(new_mac)
			current_mac = new_mac
		}
		time.Sleep(1 * time.Minute)
	}
}
