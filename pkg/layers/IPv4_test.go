package layers

import (
	"encoding/hex"
	"testing"
)

func TestCalcIPCheckSum(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x1c, 0x74, 0x68, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x64, 0x01, 0xab, 0x46, 0x9c, 0xe9}
	t.Logf("origin: %v\n", hex.EncodeToString(packet))
	CalcIPCheckSum(packet)
	t.Logf("result: %v\n", hex.EncodeToString(packet))
}

func TestCalcTCPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("450000888c1740004006645cc0a8640cc0a8649f3b3e1f4762d7f65e7129ec7b801801f6102900000101080aa0c0b95d361fc93e0000420104000441a783c3c204986105b3b96c89091a6d42fb8b6772d9b9234da863696b3d89c1c00f089e227bd2107fea2ffd3c504a19432b6e00412059723038220237a42be01083bfbe0001d40000000441a7")
	t.Logf("origin: %v\n", hex.EncodeToString(packet))
	CalcTCPCheckSum(packet)
	//0x1029
	t.Logf("result: %v\n", hex.EncodeToString(packet))
}

func TestCalcUDPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("4500002552f000008011aae7c0a8016a0b6f6f6ff83d30390011b12d68656c6c6f20554450")
	t.Logf("origin: %v\n", hex.EncodeToString(packet))
	CalcUDPCheckSum(packet)
	//0xb12d
	t.Logf("result: %v\n", hex.EncodeToString(packet))
}

func TestCalcICMPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("4500003dfb790000400134fac0a8649fc0a8645c0000eb49000100116162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a")
	t.Logf("origin: %v\n", hex.EncodeToString(packet))
	CalcICMPCheckSum(packet)
	//0xeb49
	t.Logf("result: %v\n", hex.EncodeToString(packet))
}
