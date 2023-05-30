package helpers

import (
	"net"
)

func ConvertMacToUint(macAddress string) ([]uint8, error) {
	return net.ParseMAC(macAddress)
}
