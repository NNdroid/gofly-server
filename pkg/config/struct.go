package config

type Config struct {
	VTun VTunConfig `yaml:"vtun"`
	Wg   WGConfig   `yaml:"wg"`
}

type VTunConfig struct {
	DeviceName                string `yaml:"device_name"`
	LocalAddr                 string `yaml:"local_addr"`
	ServerAddr                string `yaml:"server_addr"`
	ServerIP                  string `yaml:"server_ip"`
	ServerIPv6                string `yaml:"server_i_pv_6"`
	CIDR                      string `yaml:"cidr"`
	CIDRv6                    string `yaml:"cid_rv_6"`
	Key                       string `yaml:"key"`
	Protocol                  string `yaml:"protocol"`
	Path                      string `yaml:"path"`
	ServerMode                bool   `yaml:"server_mode"`
	GlobalMode                bool   `yaml:"global_mode"`
	Obfs                      bool   `yaml:"obfs"`
	Compress                  bool   `yaml:"compress"`
	MTU                       int    `yaml:"mtu"`
	Timeout                   int    `yaml:"timeout"`
	LocalGateway              string `yaml:"local_gateway"`
	LocalGatewayv6            string `yaml:"local_gatewayv_6"`
	TLSCertificateFilePath    string `yaml:"tls_certificate_file_path"`
	TLSCertificateKeyFilePath string `yaml:"tls_certificate_key_file_path"`
	TLSSni                    string `yaml:"tls_sni"`
	TLSInsecureSkipVerify     bool   `yaml:"tls_insecure_skip_verify"`
	BufferSize                int    `yaml:"buffer_size"`
	Verbose                   bool   `yaml:"verbose"`
	PSKMode                   bool   `yaml:"psk_mode"`
	Host                      string `yaml:"host"`
}

type WGConfig struct {
	SecretKey string   `yaml:"secret_key"`
	Address   []string `yaml:"address"`
	Peers     []WGPeer `yaml:"peers"`
	DNS       []string `yaml:"dns"`
	MTU       int      `yaml:"mtu"`
}

type WGPeer struct {
	EndPoint     string `yaml:"end_point"`
	PublicKey    string `yaml:"public_key"`
	PreSharedKey string `yaml:"preshared_key"`
}

func (config *Config) setDefault() {
}
