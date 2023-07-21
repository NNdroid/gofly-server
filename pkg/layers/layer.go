package layers

import (
	"errors"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"net"
)

type Layer struct {
	V4Layer *ipv4.V4Layer
	V6Layer *ipv6.V6Layer
	Address []net.IP
}

func (x *Layer) LoadAddress(address []string) {
	for _, addr := range address {
		x.Address = append(x.Address, net.ParseIP(addr))
	}
}

func (x *Layer) IsLocalIP(ip net.IP) bool {
	for _, addr := range x.Address {
		if addr.Equal(ip) {
			return true
		}
	}
	return false
}

func (x *Layer) IsLocalSrcPacket(packet []byte) (bool, error) {
	version := packet[0] >> 4
	var ip net.IP
	if version == 4 {
		ip = net.IP{packet[12], packet[13], packet[14], packet[15]}
	} else if version == 6 {
		ip = net.IP{packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14], packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21], packet[22], packet[23]}
	} else {
		return false, errors.New("unknown ip version")
	}
	return x.IsLocalIP(ip), nil
}

func (x *Layer) IsLocalDstPacket(packet []byte) (bool, error) {
	version := packet[0] >> 4
	var ip net.IP
	if version == 4 {
		ip = net.IP{packet[16], packet[17], packet[18], packet[19]}
	} else if version == 6 {
		ip = net.IP{packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30], packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37], packet[38], packet[39]}
	} else {
		return false, errors.New("unknown ip version")
	}
	return x.IsLocalIP(ip), nil
}
