package logger

import (
	"encoding/json"
	"go.uber.org/zap"
)

var (
	Logger *zap.Logger
	Cfg    zap.Config
)

func Init() {
	rawJSON := []byte(`{
		"level": "debug",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
		"encoding": "json",
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase"
		}
	}`)
	if err := json.Unmarshal(rawJSON, &Cfg); err != nil {
		panic(err)
	}
	l, err := Cfg.Build()

	if err != nil {
		panic(err)
	}

	Logger = l
}
