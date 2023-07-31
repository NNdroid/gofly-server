package gofly

import (
	"bytes"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"gofly/pkg/config"
	"gofly/pkg/logger"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// serialize the config into an IPC request
func createIPCRequest(config *config.Config) string {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", config.WireGuardSettings.SecretKey))

	for _, peer := range config.WireGuardSettings.Peers {
		endpoint, err := parseEndpoints(peer.EndPoint)
		if err != nil {
			logger.Logger.Sugar().Error(zap.Error(err))
			os.Exit(-1)
		}
		var appendPSKText = ""
		if peer.PreSharedKey != "" {
			appendPSKText = fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey)
		}
		request.WriteString(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n%s",
			peer.PublicKey, endpoint.String(), peer.KeepAlive, appendPSKText))
		for _, ip := range peer.AllowedIPs {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}
	return request.String()[:request.Len()]
}

var IPv6AddrPortRegex = regexp.MustCompile("^\\[([a-f0-9A-F:]{2,})\\]\\:([0-9]{1,})$")

// convert endpoint string to netip.AddrPort
func parseEndpoints(endpoint string) (*netip.AddrPort, error) {
	var addr netip.Addr
	var port uint16 = 2080
	var err error
	if strings.Count(endpoint, ":") > 1 {
		//ipv6
		matchArr := IPv6AddrPortRegex.FindStringSubmatch(endpoint)
		if len(matchArr) < 3 {
			return nil, errors.New("it not is ipv6 address")
		}
		_port, err := strconv.Atoi(matchArr[2])
		if err != nil {
			return nil, err
		}
		endpoint = matchArr[1]
		port = uint16(_port)
	} else {
		//ipv4 or domain
		if strings.Contains(endpoint, ":") {
			sp := strings.Split(endpoint, ":")
			_port, err := strconv.Atoi(sp[1])
			if err != nil {
				return nil, err
			}
			endpoint = sp[0]
			port = uint16(_port)
		}
		if IsDomainName(endpoint) {
			ip, err := LookupDomainFirst(endpoint)
			if err != nil {
				return nil, err
			}
			endpoint = ip.String()
		}
	}
	addr, err = netip.ParseAddr(endpoint)
	if err != nil {
		return nil, err
	}
	result := netip.AddrPortFrom(addr, port)
	return &result, nil
}

func LookupDomain(domain string) ([]net.IP, error) {
	return net.LookupIP(domain)
}

func LookupDomainFirst(domain string) (net.IP, error) {
	ips, err := LookupDomain(domain)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

func IsDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partLen++
		case '0' <= c && c <= '9':
			partLen++
		case c == '-':
			if last == '.' {
				return false
			}
			partLen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partLen > 63 || partLen == 0 {
				return false
			}
			partLen = 0
		}
		last = c
	}
	if last == '-' || partLen > 63 {
		return false
	}
	return nonNumeric
}
