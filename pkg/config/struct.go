package config

import (
	"errors"
)

type IPluginConfig interface {
	Check() error
}

type Server struct {
}

type Config struct {
	VTunSettings      VTunConfig      `yaml:"vTunSettings"`
	WireGuardSettings WireGuardConfig `yaml:"wgSettings"`
	WebSocketSettings WebSocketConfig `yaml:"wsSettings"`
	RealitySettings   RealityConfig   `yaml:"realitySettings"`
}

type VTunConfig struct {
	LocalAddr       string `yaml:"local_addr"`
	Key             string `yaml:"key"`
	Protocol        string `yaml:"protocol"`
	Obfs            bool   `yaml:"obfs"`
	Compress        bool   `yaml:"compress"`
	MTU             int    `yaml:"mtu"`
	Timeout         int    `yaml:"timeout"` //Unit second
	BufferSize      int    `yaml:"buffer_size"`
	Verbose         bool   `yaml:"verbose"`
	ClientIsolation bool   `yaml:"client_isolation"`
}

type WebSocketConfig struct {
	Path                      string `yaml:"path"`
	TLSCertificateFilePath    string `yaml:"tls_certificate_file_path"`
	TLSCertificateKeyFilePath string `yaml:"tls_certificate_key_file_path"`
}

func (c *WebSocketConfig) Check() error {
	if c.Path == "" {
		c.Path = "/"
	}
	return nil
}

type WireGuardConfig struct {
	SecretKey string          `yaml:"secret_key"`
	Address   []string        `yaml:"address"`
	Peers     []WireGuardPeer `yaml:"peers"`
	DNS       []string        `yaml:"dns"`
	MTU       int             `yaml:"mtu"`
}

type RealityConfig struct {
	ShortID     []string `yaml:"short_id"`
	ServerNames []string `yaml:"server_names"`
	Dest        string   `yaml:"dest"`
	PrivateKey  string   `yaml:"private_key"`
	Debug       bool     `yaml:"debug"`
}

func (c *RealityConfig) Check() error {
	if len(c.ShortID) == 0 {
		return errors.New("shortId can not empty")
	}
	if len(c.ServerNames) == 0 {
		return errors.New("serverNames can not empty")
	}
	if c.Dest == "" {
		return errors.New("dest can not empty")
	}
	if c.PrivateKey == "" {
		return errors.New("privateKey can not empty")
	}
	return nil
}

type WireGuardPeer struct {
	EndPoint     string   `yaml:"end_point"`
	PublicKey    string   `yaml:"public_key"`
	PreSharedKey string   `yaml:"preshared_key"`
	KeepAlive    int      `yaml:"keep_alive"`
	AllowedIPs   []string `yaml:"allowed_ips"`
}

func (config *Config) setDefault() {
	if config.VTunSettings.BufferSize == 0 {
		config.VTunSettings.BufferSize = 65535
	}
	if config.VTunSettings.Protocol == "" {
		config.VTunSettings.Protocol = "ws"
	}
	if config.VTunSettings.MTU == 0 {
		config.VTunSettings.MTU = 1420
	}
	if config.VTunSettings.Timeout == 0 {
		config.VTunSettings.Timeout = 60
	}
	for i, peer := range config.WireGuardSettings.Peers {
		if len(peer.AllowedIPs) == 0 {
			config.WireGuardSettings.Peers[i].AllowedIPs = append(config.WireGuardSettings.Peers[i].AllowedIPs, "0.0.0.0/0", "::/0")
			break
		}
	}
}

func (config *Config) Check() error {
	return nil
}
