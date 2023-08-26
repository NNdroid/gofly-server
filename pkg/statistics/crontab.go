package statistics

import (
	"go.uber.org/zap"
	"gofly/pkg/logger"
	"time"
)

func (x *Statistics) EnableCronTask() {
	//auto Statistics reset
	_, err := cron.Every(1).Day().At("00:00").Do(x.CleanClientList)
	if err != nil {
		logger.Logger.Error("statistics reset task start failed: ", zap.Error(err))
		return
	}
	logger.Logger.Info("statistics reset task started")

	//daily chart data
	_, err = cron.Every(1).Day().At("23:55").Do(x.CleanDailyChartData)
	if err != nil {
		logger.Logger.Error("daily chart data start failed: ", zap.Error(err))
		return
	}
	logger.Logger.Info("daily chart data task started")

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

func (x *Statistics) CleanDailyChartData() {
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
