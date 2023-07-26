package statistics

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Time time.Time

func (t Time) String() string {
	return time.Time(t).Format("2006-01-02 15:04:05")
}

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte("\"" + t.String() + "\""), nil
}

type ClientData struct {
	Addr        net.Addr `json:"addr"`
	OnlineTime  Time     `json:"online_time"`
	OfflineTime Time     `json:"offline_time"`
	Online      bool     `json:"online"`
	RX          uint64   `json:"rx"`
	TX          uint64   `json:"tx"`
}

type ChartData struct {
	mutex          sync.Mutex
	previousRX     uint64
	previousTX     uint64
	transportBytes []int
	receiveBytes   []int
	labels         []string
	count          int
}

type Statistics struct {
	mutex             sync.Mutex
	OnlineClientCount int
	ClientList        []ClientData
	RX                uint64
	TX                uint64
	ChartData         ChartData
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
		x.ClientList[i].OfflineTime = Time(time.Now())
	}
}

func (x *Statistics) Push(y net.Addr) {
	if _, ok := x.Contains(y); !ok {
		x.mutex.Lock()
		defer x.mutex.Unlock()
		x.ClientList = append(x.ClientList, ClientData{Addr: y, Online: true, OnlineTime: Time(time.Now())})
		x.OnlineClientCount++
		keyMap[y.String()] = len(x.ClientList) - 1
	}
}

func (x *Statistics) AutoUpdateChartData() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var currentTX = x.TX //TX is the total received by all clients
		var currentRX = x.RX //RX is the total number of transfers from all clients
		if currentTX == 0 && currentRX == 0 {
			continue
		}
		x.mutex.Lock()
		if x.ChartData.count < 1800 {
			x.ChartData.labels = append(x.ChartData.labels, time.Now().Format("15:04:05"))
			x.ChartData.transportBytes = append(x.ChartData.transportBytes, int(currentRX-x.ChartData.previousRX))
			x.ChartData.receiveBytes = append(x.ChartData.receiveBytes, int(currentTX-x.ChartData.previousTX))
			x.ChartData.count++
		} else {
			x.ChartData.labels = append(x.ChartData.labels[1:], time.Now().Format("15:04:05"))
			x.ChartData.transportBytes = append(x.ChartData.transportBytes[1:], int(currentRX-x.ChartData.previousRX))
			x.ChartData.receiveBytes = append(x.ChartData.receiveBytes[1:], int(currentTX-x.ChartData.previousTX))
		}
		x.mutex.Unlock()
		x.ChartData.previousTX = currentTX
		x.ChartData.previousRX = currentRX
	}
}

func (x *ChartData) GetData() ([]int, []int, []string, int) {
	x.mutex.Lock()
	defer x.mutex.Unlock()
	return x.transportBytes, x.receiveBytes, x.labels, x.count
}
