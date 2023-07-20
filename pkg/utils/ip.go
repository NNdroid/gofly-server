package utils

import "strings"

func IsIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
