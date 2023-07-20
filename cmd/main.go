package main

import (
	"flag"
	"go.uber.org/zap"
	"gofly"
	"gofly/pkg/commonio"
	"gofly/pkg/config"
	"gofly/pkg/logger"
)

var _configFilePath string
var _flagQuiet bool
var _config *config.Config

func init() {
	logger.Init()
	flag.StringVar(&_configFilePath, "c", "config.yaml", "the path of configuration file")
	flag.BoolVar(&_flagQuiet, "quiet", false, "quiet for log print.")
	flag.Parse()
	if _flagQuiet {
		logger.Cfg.Level.SetLevel(zap.ErrorLevel)
	}
	if !commonio.IsFile(_configFilePath) || !commonio.ExistsFile(_configFilePath) {
		logger.Logger.Fatal("configure file not found!")
	}
	dat, err := commonio.ReadFile(_configFilePath)
	if err != nil {
		logger.Logger.Fatal("read configure file fail!", zap.Error(err))
	}
	_config, err = config.Parse(dat)
	if err != nil {
		logger.Logger.Fatal("parse configure file fail!", zap.Error(err))
	}
}

func main() {
	gofly.StartServer(_config)
}
