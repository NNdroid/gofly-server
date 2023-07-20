package config

import (
	"gopkg.in/yaml.v3"
)

func Parse(text []byte) (*Config, error) {
	var config Config
	err := yaml.Unmarshal(text, &config)
	if err != nil {
		return &config, err
	}
	config.setDefault()
	return &config, nil
}
