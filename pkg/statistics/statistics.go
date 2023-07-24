package statistics

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ClientData struct {
	Addr        net.Addr  `json:"addr"`
	OnlineTime  time.Time `json:"online_time"`
	OfflineTime time.Time `json:"offline_time"`
	Online      bool      `json:"online"`
	RX          uint64    `json:"rx"`
	TX          uint64    `json:"tx"`
}

type Statistics struct {
	mutex             sync.Mutex
	OnlineClientCount int
	ClientList        []ClientData
	RX                uint64
	TX                uint64
}

var keyMap = make(map[string]int)

func (x *Statistics) IncrClientReceivedBytes(y net.Addr, n int) {
	if i, ok := x.Contains(y); ok {
		atomic.AddUint64(&x.ClientList[i].RX, uint64(n))
	}
}

func (x *Statistics) IncrClientTransportBytes(y net.Addr, n int) {
	if i, ok := x.Contains(y); ok {
		atomic.AddUint64(&x.ClientList[i].TX, uint64(n))
	}
}

func (x *Statistics) IncrReceivedBytes(n int) {
	atomic.AddUint64(&x.RX, uint64(n))
}

func (x *Statistics) IncrTransportBytes(n int) {
	atomic.AddUint64(&x.TX, uint64(n))
}

func (x *Statistics) Contains(y net.Addr) (int, bool) {
	if v, ok := keyMap[y.String()]; ok {
		return v, true
	}
	for i, client := range x.ClientList {
		if client.Addr.String() == y.String() && client.Addr.Network() == y.Network() && client.Online {
			return i, true
		}
	}
	return -1, false
}

func (x *Statistics) Remove(y net.Addr) {
	i, ok := x.Contains(y)
	if ok {
		x.mutex.Lock()
		defer x.mutex.Unlock()
		//x.OnlineClientList = append(x.OnlineClientList[:i], x.OnlineClientList[i+1:]...)
		delete(keyMap, y.String())
		x.OnlineClientCount--
		x.ClientList[i].Online = false
		x.ClientList[i].OfflineTime = time.Now()
	}
}

func (x *Statistics) Push(y net.Addr) {
	if _, ok := x.Contains(y); !ok {
		x.mutex.Lock()
		defer x.mutex.Unlock()
		x.ClientList = append(x.ClientList, ClientData{Addr: y, Online: true, OnlineTime: time.Now()})
		x.OnlineClientCount++
		keyMap[y.String()] = len(x.ClientList) - 1
	}
}
