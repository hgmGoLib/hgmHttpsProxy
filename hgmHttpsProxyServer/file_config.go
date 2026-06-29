package hgmHttpsProxyServer

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
)

// ServerFileConfig 网关的「文件态/可远程下发」JSON 配置。放在本包并导出,方便上层代码直接
// 远程写这份 JSON 再让网关进程读取启动(serve 子命令即如此)。证书相关字段聚到 ServerTlsCert
// 指针下;其余字段与 ServerConfig 一一对应(函数型注入点如 DialUpstream 只能代码对接,不进 JSON)。
type ServerFileConfig struct {
	Listen        string            // 如 ":9443"
	ServerTlsCert *ServerTlsCert    // 服务端证书来源;nil = 内存生成一张自签证书(明文需另行约定,这里默认 https)
	AcceptedBasic map[string]string // user → pass(空 = 不要求账号密码)
	ClientCaPins  []string          // 客户端上一级 CA 的 SPKI pin(空 = 不要求客户端证书)
	AllowedCIDRs  []string          // 允许来源网段(空 = 不限)
	TargetAllowlist []string        // 允许 CONNECT 的目标 host:port(空 = 不限)

	RelayIdleTimeoutSeconds int // 隧道空闲超时(秒):0 = 默认 2 分钟;负数 = 永不超时

	// DisplayIP 启动后打印监听 URL 时使用的 IP(空 = 127.0.0.1)。仅影响打印出来给人看的
	// 那个 URL,不影响实际监听地址(实际监听由 Listen 决定,常为 0.0.0.0/全网卡)。
	DisplayIP string
}

// ServerTlsCert 服务端 TLS 证书来源。证书与私钥各自在「内嵌 PEM」与「文件路径」里二选一:
//   - 内嵌组:TLSCertPEM / TLSKeyPEM —— 直接放 PEM 文本
//   - 文件组:TLSCertFile / TLSKeyFile —— 放文件路径;两个文件都不存在则首次启动自动生成并落盘
type ServerTlsCert struct {
	TLSCertPEM  string // 内嵌 PEM 文本
	TLSKeyPEM   string // 内嵌 PEM 文本
	TLSCertFile string // 文件路径
	TLSKeyFile  string // 文件路径
}

// ToServerConfig 把文件态配置解析成 ServerConfig(不含 OnAudit 等函数型注入点,由调用方按需补)。
//   - ServerTlsCert == nil:内存生成一张自签证书(SAN=127.0.0.1)
//   - 内嵌组/文件组:各取一份 PEM
//   - 文件组且两个文件都不存在:首次启动自动生成证书+私钥并写入这两个文件
func (fc *ServerFileConfig) ToServerConfig() (ServerConfig, error) {
	cfg := ServerConfig{
		Listen:           fc.Listen,
		AcceptedBasic:    fc.AcceptedBasic,
		AllowedCIDRs:     fc.AllowedCIDRs,
		TargetAllowlist:  fc.TargetAllowlist,
		RelayIdleTimeout: time.Duration(fc.RelayIdleTimeoutSeconds) * time.Second, // 0 → NewServer 兜底 2 分钟
	}
	certPEM, keyPEM, err := fc.ServerTlsCert.resolve()
	if err != nil {
		return ServerConfig{}, err
	}
	cfg.TLSCertPEM, cfg.TLSKeyPEM = certPEM, keyPEM
	if len(fc.ClientCaPins) > 0 {
		if cfg.ClientCaPins, err = hgmHttpsProxyClient.ParsePins(strings.Join(fc.ClientCaPins, ",")); err != nil {
			return ServerConfig{}, fmt.Errorf("ClientCaPins: %w", err)
		}
	}
	return cfg, nil
}

// resolve 取出服务端证书的 PEM。nil 接收者(配置未填 ServerTlsCert)= 内存生成自签证书。
func (c *ServerTlsCert) resolve() (certPEM, keyPEM []byte, err error) {
	if c == nil {
		return GenServerCert("hgmHttpsProxy-gateway", nil, []string{"127.0.0.1"}, 825)
	}
	hasInline := c.TLSCertPEM != "" || c.TLSKeyPEM != ""
	hasFile := c.TLSCertFile != "" || c.TLSKeyFile != ""
	switch {
	case hasInline && hasFile:
		return nil, nil, errors.New("ServerTlsCert: 内嵌 PEM 与文件路径只能二选一")
	case hasInline:
		if c.TLSCertPEM == "" || c.TLSKeyPEM == "" {
			return nil, nil, errors.New("ServerTlsCert: TLSCertPEM / TLSKeyPEM 必须同时提供")
		}
		return []byte(c.TLSCertPEM), []byte(c.TLSKeyPEM), nil
	case hasFile:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return nil, nil, errors.New("ServerTlsCert: TLSCertFile / TLSKeyFile 必须同时提供")
		}
		return loadOrGenCertFiles(c.TLSCertFile, c.TLSKeyFile)
	default:
		// 空结构体等同未配置:内存生成自签证书。
		return GenServerCert("hgmHttpsProxy-gateway", nil, []string{"127.0.0.1"}, 825)
	}
}

// loadOrGenCertFiles:两个文件都在就读;都不在就首次启动自动生成证书+私钥并落盘(.crt 0644、
// .key 0600);只存在其一视为状态损坏,报错(避免拿半套证书启动)。
func loadOrGenCertFiles(certFile, keyFile string) (certPEM, keyPEM []byte, err error) {
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)
	switch {
	case certExists && keyExists:
		if certPEM, err = os.ReadFile(certFile); err != nil {
			return nil, nil, fmt.Errorf("读 TLSCertFile %s: %w", certFile, err)
		}
		if keyPEM, err = os.ReadFile(keyFile); err != nil {
			return nil, nil, fmt.Errorf("读 TLSKeyFile %s: %w", keyFile, err)
		}
		return certPEM, keyPEM, nil
	case !certExists && !keyExists:
		certPEM, keyPEM, err = GenServerCert("hgmHttpsProxy-gateway", nil, []string{"127.0.0.1"}, 825)
		if err != nil {
			return nil, nil, fmt.Errorf("首次启动生成服务端证书: %w", err)
		}
		if err = os.WriteFile(certFile, certPEM, 0o644); err != nil {
			return nil, nil, fmt.Errorf("写 TLSCertFile %s: %w", certFile, err)
		}
		if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return nil, nil, fmt.Errorf("写 TLSKeyFile %s: %w", keyFile, err)
		}
		return certPEM, keyPEM, nil
	default:
		return nil, nil, fmt.Errorf("ServerTlsCert: %s 与 %s 必须同时存在或同时不存在(当前只有一个存在,拒绝半套证书启动)", certFile, keyFile)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
