package main

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"gofly"
	"gofly/pkg/config"
	"gofly/pkg/logger"
	"gofly/pkg/utils"
	"log"
	"os"
)

var (
	_configFilePath string
	_flagQuiet      bool
	_config         *config.Config
	_flagVersion    bool
	_flagX25519     bool
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
	logger.Init()
	flag.StringVar(&_configFilePath, "c", "config.yaml", "the path of configuration file")
	flag.BoolVar(&_flagQuiet, "quiet", false, "quiet for log print.")
	flag.BoolVar(&_flagVersion, "v", false, "print version info.")
	flag.BoolVar(&_flagX25519, "x25519", false, "generate a new x25519 key.")
	flag.Parse()
	if _flagVersion {
		displayVersionInfo()
		os.Exit(0)
	}
	if _flagX25519 {
		x25519, err := executeX25519()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(x25519)
		os.Exit(0)
	}
	log.Printf("\n __    _    \n/__ _ |_|   \n\\_|(_)| |\\/ \n         /  ")
	if _flagQuiet {
		logger.Cfg.Level.SetLevel(zap.ErrorLevel)
	}
	if !utils.IsFile(_configFilePath) || !utils.ExistsFile(_configFilePath) {
		logger.Logger.Fatal("configure file not found!")
	}
	dat, err := utils.ReadFile(_configFilePath)
	if err != nil {
		logger.Logger.Fatal("read configure file fail!", zap.Error(err))
	}
	_config, err = config.Parse(dat)
	if err != nil {
		logger.Logger.Fatal("parse configure file fail!", zap.Error(err))
	}
	err = _config.Check()
	if err != nil {
		logger.Logger.Fatal("check configure fail!", zap.Error(err))
	}
	if _flagQuiet {
		_config.VTunSettings.Verbose = false
	}
}

func main() {
	gofly.StartServer(_config)
}
