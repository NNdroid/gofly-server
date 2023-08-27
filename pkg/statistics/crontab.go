package statistics

import (
	"go.uber.org/zap"
	"gofly/pkg/logger"
	"time"
)

func (x *Statistics) EnableCronTask() {
	//auto Statistics reset
	_, err := cron.Cron("0 0 * * *").Do(x.CleanClientList)
	if err != nil {
		logger.Logger.Error("statistics reset task start failed: ", zap.Error(err))
		return
	}
	logger.Logger.Info("statistics reset task started")

	//daily chart data
	_, err = cron.Cron("55 23 * * *").Do(x.AppendDailyData)
	if err != nil {
		logger.Logger.Error("daily chart data start failed: ", zap.Error(err))
		return
	}
	logger.Logger.Info("daily chart data task started")

	//per hour chart data
	_, err = cron.Cron("0 * * * *").Do(x.AppendPerHourData)
	if err != nil {
		logger.Logger.Error("per hour chart data start failed: ", zap.Error(err))
		return
	}
	logger.Logger.Info("per hour chart data task started")

	cron.StartAsync()
}

func (x *Statistics) CleanClientList() {
	x.mutex.Lock()
	defer x.mutex.Unlock()
	for i, v := range x.ClientList {
		if !v.Online {
			count := len(x.ClientList) - 1
			if count > 0 {
				x.ClientList[i] = x.ClientList[count]
			}
			x.ClientList = x.ClientList[:count]
		}
	}
}

func (x *Statistics) AppendDailyData() {
	x.DailyChartData.mutex.Lock()
	defer x.DailyChartData.mutex.Unlock()
	var currentTX = x.TX //TX is the total received by all clients
	var currentRX = x.RX //RX is the total number of transfers from all clients
	if x.DailyChartData.count < 30 {
		x.DailyChartData.transportBytes = append(x.DailyChartData.transportBytes, currentTX-x.DailyChartData.previousTX)
		x.DailyChartData.receiveBytes = append(x.DailyChartData.receiveBytes, currentRX-x.DailyChartData.previousRX)
		x.DailyChartData.labels = append(x.DailyChartData.labels, time.Now().Format("2006-01-02"))
		x.DailyChartData.count++
	} else {
		x.DailyChartData.transportBytes = append(x.DailyChartData.transportBytes[1:], currentTX-x.DailyChartData.previousTX)
		x.DailyChartData.receiveBytes = append(x.DailyChartData.receiveBytes[1:], currentRX-x.DailyChartData.previousRX)
		x.DailyChartData.labels = append(x.DailyChartData.labels[1:], time.Now().Format("2006-01-02"))
	}
	x.DailyChartData.previousTX = currentTX
	x.DailyChartData.previousRX = currentRX
}

func (x *Statistics) AppendPerHourData() {
	x.PerHourChartData.mutex.Lock()
	defer x.PerHourChartData.mutex.Unlock()
	var currentTX = x.TX //TX is the total received by all clients
	var currentRX = x.RX //RX is the total number of transfers from all clients
	if x.PerHourChartData.count < 180 {
		x.PerHourChartData.transportBytes = append(x.PerHourChartData.transportBytes, currentTX-x.PerHourChartData.previousTX)
		x.PerHourChartData.receiveBytes = append(x.PerHourChartData.receiveBytes, currentRX-x.PerHourChartData.previousRX)
		x.PerHourChartData.labels = append(x.PerHourChartData.labels, time.Now().Format("01-02  15:04"))
		x.PerHourChartData.count++
	} else {
		x.PerHourChartData.transportBytes = append(x.PerHourChartData.transportBytes[1:], currentTX-x.PerHourChartData.previousTX)
		x.PerHourChartData.receiveBytes = append(x.PerHourChartData.receiveBytes[1:], currentRX-x.PerHourChartData.previousRX)
		x.PerHourChartData.labels = append(x.PerHourChartData.labels[1:], time.Now().Format("01-02  15:04"))
	}
	x.PerHourChartData.previousTX = currentTX
	x.PerHourChartData.previousRX = currentRX
}
