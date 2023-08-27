package gofly

import (
	"github.com/gin-gonic/gin"
	"gofly/pkg/web"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
)

func RunLocalHttpServer() {
	listener, err := tNet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Panicln(err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.StaticFS("/dashboard/", http.FS(web.StaticFS))
	g1 := r.Group("/api/v1")
	g1.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	g1.GET("/myinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"connection": c.Request.RemoteAddr,
			"user-agent": c.Request.UserAgent(),
			"ip":         c.ClientIP(),
		})
	})
	g1.GET("/online/count", func(c *gin.Context) {
		c.String(http.StatusOK, strconv.Itoa(stats.OnlineClientCount))
	})
	g1.GET("/traffic", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"rx": stats.RX,
			"tx": stats.TX,
		})
	})
	g1.GET("/traffic/chart", func(c *gin.Context) {
		tbx, rbx, labels, count := stats.ChartData.GetData()
		c.JSON(http.StatusOK, gin.H{
			"receive":   rbx,
			"transport": tbx,
			"labels":    labels,
			"count":     count,
		})
	})
	g1.GET("/traffic/chart/daily", func(c *gin.Context) {
		tbx, rbx, labels, count := stats.DailyChartData.GetData()
		c.JSON(http.StatusOK, gin.H{
			"receive":   rbx,
			"transport": tbx,
			"labels":    labels,
			"count":     count,
		})
	})
	g1.GET("/traffic/chart/per_hour", func(c *gin.Context) {
		tbx, rbx, labels, count := stats.PerHourChartData.GetData()
		c.JSON(http.StatusOK, gin.H{
			"receive":   rbx,
			"transport": tbx,
			"labels":    labels,
			"count":     count,
		})
	})
	g1.GET("/clients", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"data": stats.ClientList,
		})
	})
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, ":)   this is vpn gateway!\ndashboard at /dashboard\ncopyright follow 2023")
	})
	err = r.RunListener(listener)
	if err != nil {
		log.Panicln(err)
	}
}

func RunHttpClient() {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: tNet.DialContext,
		},
	}
	resp, err := client.Get("http://172.16.222.1/")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))
}
