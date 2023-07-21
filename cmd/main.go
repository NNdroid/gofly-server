package main

import (
	"flag"
	"go.uber.org/zap"
	"gofly"
	"gofly/pkg/commonio"
	"gofly/pkg/config"
	"gofly/pkg/logger"
	"log"
	"os"
)

var (
	_configFilePath string
	_flagQuiet      bool
	_config         *config.Config
	_flagVersion    bool
)

var (
	_version   = "v1.0.20230721"
	_gitHash   = "nil"
	_buildTime = "nil"
	_goVersion = "nil"
)

func displayVersionInfo() {
	log.Printf("version %s", _version)
	log.Printf("git hash %s", _gitHash)
	log.Printf("build time %s", _buildTime)
	log.Printf("go version %s", _goVersion)
}

func init() {
	log.Printf("\n __    _    \n/__ _ |_|   \n\\_|(_)| |\\/ \n         /  ")
	logger.Init()
	flag.StringVar(&_configFilePath, "c", "config.yaml", "the path of configuration file")
	flag.BoolVar(&_flagQuiet, "quiet", false, "quiet for log print.")
	flag.BoolVar(&_flagVersion, "v", false, "print version info.")
	flag.Parse()
	if _flagVersion {
		displayVersionInfo()
		os.Exit(0)
	}
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
