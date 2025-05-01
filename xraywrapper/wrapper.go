package xraywrapper

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/confloader"
)

type XrayWrapper struct {
	instance *core.Instance
	tempFile string
}

func NewXrayWrapper() *XrayWrapper {
	return &XrayWrapper{}
}

// writeTempConfig creates a temporary file with the JSON config
func (x *XrayWrapper) writeTempConfig(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		return "", err
	}
	return tmpFile.Name(), nil
}

// loadConfig handles the config file loading process
func (x *XrayWrapper) loadConfig(jsonConfig string) (*core.Config, error) {
	// Create temporary config file
	tmpFile, err := x.writeTempConfig(jsonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp config: %v", err)
	}
	x.tempFile = tmpFile

	// Load config through standard loader
	reader, err := confloader.LoadConfig(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("config loader failed: %v", err)
	}

	// Read the full config
	configBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	// Parse the actual config
	config, err := core.LoadConfig("json", configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	return config, nil
}

// StartXray starts Xray with any supported config format
func (x *XrayWrapper) StartXray(configInput string) error {
	// Parse the configuration (auto-detects format)
	jsonConfig, err := x.ParseConfig(configInput)
	if err != nil {
		return fmt.Errorf("config parsing failed: %v", err)
	}

	// Load the configuration
	config, err := x.loadConfig(jsonConfig)
	if err != nil {
		return fmt.Errorf("config loading failed: %v", err)
	}

	// Create new Xray instance
	instance, err := core.New(config)
	if err != nil {
		return fmt.Errorf("instance creation failed: %v", err)
	}

	// Start the instance
	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start: %v", err)
	}

	x.instance = instance
	return nil
}

// StopXray cleanly shuts down the instance
func (x *XrayWrapper) StopXray() error {
	if x.instance == nil {
		return errors.New("instance not running")
	}

	// Clean up temporary file
	if x.tempFile != "" {
		os.Remove(x.tempFile)
		x.tempFile = ""
	}

	if err := x.instance.Close(); err != nil {
		return fmt.Errorf("failed to stop: %v", err)
	}

	x.instance = nil
	return nil
}

// IsRunning checks if Xray is active
func (x *XrayWrapper) IsRunning() bool {
	return x.instance != nil
}

// ParseConfig handles all protocol formats
func (x *XrayWrapper) ParseConfig(uri string) (string, error) {
	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return x.parseVmessConfig(uri)
	case strings.HasPrefix(uri, "ss://"):
		return x.parseShadowsocksConfig(uri)
	case strings.HasPrefix(uri, "vless://"):
		return x.parseVlessConfig(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return x.parseTrojanConfig(uri)
	case strings.HasPrefix(uri, "{"): // Raw JSON
		return uri, nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", uri)
	}
}

func (x *XrayWrapper) parseVmessConfig(uri string) (string, error) {
	base64Str := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(base64Str)
		if err != nil {
			return "", fmt.Errorf("base64 decode failed: %v", err)
		}
	}

	var vmess struct {
		Add  string `json:"add"`
		Port int    `json:"port"`
		ID   string `json:"id"`
		Aid  int    `json:"aid"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
	}

	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return "", fmt.Errorf("vmess parse failed: %v", err)
	}

	config := fmt.Sprintf(`{
		"inbounds": [{
			"port": 1080,
			"protocol": "socks",
			"settings": {
				"auth": "noauth",
				"udp": true
			},
			"sniffing": {
				"enabled": true,
				"destOverride": ["http", "tls"]
			}
		}],
		"outbounds": [{
			"protocol": "vmess",
			"settings": {
				"vnext": [{
					"address": "%s",
					"port": %d,
					"users": [{
						"id": "%s",
						"alterId": %d,
						"security": "auto"
					}]
				}]
			},
			"streamSettings": {
				"network": "%s",
				"security": "%s",
				"%sSettings": {
					"path": "%s",
					"headers": {
						"Host": "%s"
					}
				}
			},
			"mux": {
				"enabled": true,
				"concurrency": 8
			}
		}],
		"routing": {
			"domainStrategy": "IPIfNonMatch",
			"rules": []
		}
	}`, vmess.Add, vmess.Port, vmess.ID, vmess.Aid, vmess.Net, vmess.TLS, vmess.Net, vmess.Path, vmess.Host)

	return config, nil
}

func (x *XrayWrapper) parseShadowsocksConfig(uri string) (string, error) {
	parts := strings.SplitN(uri, "@", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid ss format")
	}

	userInfo := strings.TrimPrefix(parts[0], "ss://")
	serverInfo := parts[1]

	// Decode user info (method:password)
	userDecoded, err := base64.StdEncoding.DecodeString(userInfo)
	if err != nil {
		userDecoded, err = base64.URLEncoding.DecodeString(userInfo)
		if err != nil {
			return "", fmt.Errorf("ss decode failed: %v", err)
		}
	}

	userParts := strings.SplitN(string(userDecoded), ":", 2)
	if len(userParts) != 2 {
		return "", errors.New("invalid ss user info")
	}

	method := userParts[0]
	password := userParts[1]

	// Parse server info
	serverParts := strings.SplitN(serverInfo, ":", 2)
	if len(serverParts) != 2 {
		return "", errors.New("invalid ss server info")
	}

	server := serverParts[0]
	portStr := strings.Split(serverParts[1], "/")[0]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port: %v", err)
	}

	return fmt.Sprintf(`{
		"inbounds": [{
			"port": 1080,
			"protocol": "socks",
			"settings": {
				"auth": "noauth",
				"udp": true
			},
			"sniffing": {
				"enabled": true,
				"destOverride": ["http", "tls"]
			}
		}],
		"outbounds": [{
			"protocol": "shadowsocks",
			"settings": {
				"servers": [{
					"address": "%s",
					"port": %d,
					"method": "%s",
					"password": "%s"
				}]
			},
			"streamSettings": {
				"network": "tcp"
			}
		}]
	}`, server, port, method, password), nil
}

func (x *XrayWrapper) parseVlessConfig(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("vless parse failed: %v", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", fmt.Errorf("invalid port: %v", err)
	}

	query := u.Query()
	security := query.Get("security")
	if security == "" {
		security = "tls"
	}

	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}

	flow := query.Get("flow")
	if flow == "" {
		flow = "xtls-rprx-direct"
	}

	return fmt.Sprintf(`{
		"inbounds": [{
			"port": 1080,
			"protocol": "socks",
			"settings": {
				"auth": "noauth",
				"udp": true
			}
		}],
		"outbounds": [{
			"protocol": "vless",
			"settings": {
				"vnext": [{
					"address": "%s",
					"port": %d,
					"users": [{
						"id": "%s",
						"flow": "%s"
					}]
				}]
			},
			"streamSettings": {
				"network": "%s",
				"security": "%s",
				"%sSettings": {
					"path": "%s",
					"headers": {
						"Host": "%s"
					}
				}
			}
		}]
	}`, u.Hostname(), port, u.User.Username(), flow, network, security, network,
		query.Get("path"), query.Get("host")), nil
}

func (x *XrayWrapper) parseTrojanConfig(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("trojan parse failed: %v", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", fmt.Errorf("invalid port: %v", err)
	}

	query := u.Query()
	security := query.Get("security")
	if security == "" {
		security = "tls"
	}

	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}

	return fmt.Sprintf(`{
		"inbounds": [{
			"port": 1080,
			"protocol": "socks",
			"settings": {
				"auth": "noauth",
				"udp": true
			}
		}],
		"outbounds": [{
			"protocol": "trojan",
			"settings": {
				"servers": [{
					"address": "%s",
					"port": %d,
					"password": "%s"
				}]
			},
			"streamSettings": {
				"network": "%s",
				"security": "%s",
				"%sSettings": {
					"path": "%s",
					"headers": {
						"Host": "%s"
					}
				}
			}
		}]
	}`, u.Hostname(), port, u.User.Username(), network, security, network,
		query.Get("path"), query.Get("host")), nil
}
