package hgmHttpsProxyClient

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ClientConfig 端点侧出口代理配置,从一个 forward_to URL 静态解析(配置一次)。
//
// forward_to 形如:
//
//	https://user:pass@gw.example.com:9443?serverPins=sha256:AAA,sha256:BBB&nosni=1
//	http://user:pass@10.0.0.1:8080   (明文外层,仅防不了被动监听,报不安全)
//
// query 参数:
//   - serverPins   服务端叶子证书 SPKI pin(逗号分隔,命中任一即信任;空=不校验服务端)
//   - clientCaPins 客户端上一级 CA 的 SPKI pin —— 由服务端消费,这里仅留作安全分级展示
//   - nosni=1      不发送 SNI(避免明文域名被过滤;仅在要求 TLS1.3 时才真正藏住域名)
type ClientConfig struct {
	Scheme     string // https / http
	Host       string // host:port(已补默认端口)
	User       string
	Pass       string
	ServerPins []Pin
	NoSNI      bool

	// 客户端证书(双向 TLS),供服务端 clientCaPins 校验。PEM,由集成方注入(如复用 enrollment 证书)。
	ClientCertPEM []byte
	ClientKeyPEM  []byte

	// DialTimeout 拨号+TLS 握手超时,0 用默认 10s。
	DialTimeout time.Duration

	clientCaPinsRaw string // 原样保留,仅供 Security() 分级
}

// ParseForwardURL 从 forward_to URL 解析配置。
func ParseForwardURL(forwardTo string) (*ClientConfig, error) {
	u, err := url.Parse(forwardTo)
	if err != nil {
		return nil, fmt.Errorf("解析 forward_to: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("forward_to scheme 必须 http/https,收到 %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("forward_to 缺 host:port")
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	cfg := &ClientConfig{Scheme: scheme, Host: host}
	if u.User != nil {
		cfg.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			cfg.Pass = p
		}
	}
	q := u.Query()
	if cfg.ServerPins, err = ParsePins(q.Get("serverPins")); err != nil {
		return nil, err
	}
	cfg.clientCaPinsRaw = strings.TrimSpace(q.Get("clientCaPins"))
	cfg.NoSNI = q.Get("nosni") == "1"
	return cfg, nil
}

// Security 返回该配置的安全等级。
func (c *ClientConfig) Security() SecurityLevel {
	return ClassifySecurity(c.Scheme, len(c.ServerPins) > 0, c.clientCaPinsRaw != "", c.User != "" || c.Pass != "")
}

// ProxyAuthHeader 返回 Proxy-Authorization 头值(可空)。
func (c *ClientConfig) ProxyAuthHeader() string { return EncodeBasicAuth(c.User, c.Pass) }

// DialResp 一次 CONNECT 拨号的结果对象。成功与失败都返回(永不为 nil),让调用方直接按
// Status 分类,而无需解析 err 文案。
type DialResp struct {
	// Conn 成功(Status==200)时为到目标的隧道 conn;失败为 nil。
	Conn net.Conn
	// Status 网关对 CONNECT 的响应状态码:
	//   - 拿到网关响应:实际码(200 成功 / 403 / 407 / ...);非 200 时 Conn=nil 且 err 非 nil。
	//   - 没拿到响应(拨号失败 / 外层 TLS 握手失败 / 读响应失败):0,此时 err 区分具体阶段。
	Status int
	// Phrase 响应原因短语(可空)。
	Phrase string
}

// Dial 经出口代理建立到 targetHostPort 的隧道,返回隧道 net.Conn(已发 CONNECT 且收到 200)。
// extraHeaders 可注入审计头(如 X-Endpoint-Id),值不得含 CRLF,可为 nil。
// 等价于 DialContext(context.Background(), ...),并丢弃 DialResp(只关心成功/失败时用本入口;
// 接 http.Transport.DialContext / gRPC dialer 等只认 (net.Conn, error) 的调用栈也用它)。
func (c *ClientConfig) Dial(targetHostPort string, extraHeaders map[string]string) (net.Conn, error) {
	resp, err := c.DialContext(context.Background(), targetHostPort, extraHeaders)
	return resp.Conn, err
}

// DialContext 同 Dial,但拨号 / TLS 握手 / CONNECT 收发都跟随 ctx 的取消与截止时间,且返回
// DialResp 对象(Status 供调用方按码分类,无需解析 err 文案)。resp 永不为 nil。
// ctx 无 deadline 时按 DialTimeout(默认 10s)派生一个,所以 ctx 取消或超时都会让本调用尽快返回。
func (c *ClientConfig) DialContext(ctx context.Context, targetHostPort string, extraHeaders map[string]string) (*DialResp, error) {
	if _, _, err := net.SplitHostPort(targetHostPort); err != nil {
		return &DialResp{}, fmt.Errorf("非法目标 %q: %w", targetHostPort, err)
	}
	// ctx 无 deadline 时用 DialTimeout 派生一个,统一交给 dial/握手/CONNECT 兜底。
	if _, ok := ctx.Deadline(); !ok {
		timeout := c.DialTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", c.Host)
	if err != nil {
		return &DialResp{}, fmt.Errorf("拨号网关 %s: %w", c.Host, err)
	}
	var conn net.Conn = raw
	if c.Scheme == "https" {
		tlsCfg, terr := c.tlsConfig()
		if terr != nil {
			raw.Close()
			return &DialResp{}, terr
		}
		// 用 tls.Client(而非 tls.Dial)以便完全掌控 SNI:tls.Dial 会在 ServerName 为空时
		// 用拨号地址回填 SNI,nosni 就失效了。HandshakeContext 让握手也跟随 ctx。
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return &DialResp{}, fmt.Errorf("TLS 握手 %s: %w", c.Host, err)
		}
		conn = tc
	}
	// CONNECT 收发阶段用 ctx 的 deadline 兜底(ctx 已派生 deadline,取消时 deadline 即过)。
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if err := WriteConnectRequest(conn, targetHostPort, c.ProxyAuthHeader(), extraHeaders); err != nil {
		conn.Close()
		return &DialResp{}, fmt.Errorf("写 CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	code, phrase, _, err := ReadConnectResponseStatus(br)
	if err != nil {
		conn.Close()
		return &DialResp{}, fmt.Errorf("读 CONNECT 响应: %w", err)
	}
	if code != 200 {
		conn.Close()
		return &DialResp{Status: code, Phrase: phrase}, fmt.Errorf("网关拒绝 CONNECT: %d %s", code, phrase)
	}
	_ = conn.SetDeadline(time.Time{}) // 清超时,允许长连接
	return &DialResp{Conn: &BufferedConn{Conn: conn, R: br}, Status: code, Phrase: phrase}, nil
}

// tlsConfig 构造端点 dial 网关的 TLS 配置。
func (c *ClientConfig) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, // 设计要求:最低 TLS1.3(证书加密、无降级、nosni 才有意义)
		// 无 serverPins 时按设计「不关注服务端证书」(可自签可公网);有 pin 时下面挂自定义校验。
		// 两种情况都跳过标准 CA 校验,故 InsecureSkipVerify=true。
		InsecureSkipVerify: true, //nolint:gosec // 出口代理刻意不验 CA,安全性由 serverPins 提供
	}
	if !c.NoSNI {
		serverName := c.Host
		if h, _, err := net.SplitHostPort(c.Host); err == nil {
			serverName = h
		}
		cfg.ServerName = serverName
	}
	if len(c.ServerPins) > 0 {
		pins := c.ServerPins
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// InsecureSkipVerify=true 时 verifiedChains 为 nil,只能自己 parse rawCerts[0]。
			if len(rawCerts) == 0 {
				return errors.New("服务端未提供证书")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("解析服务端叶子证书: %w", err)
			}
			if !MatchSPKIPin(pins, leaf) {
				return errors.New("服务端证书 serverPins 不匹配(fail-closed)")
			}
			return nil
		}
	}
	if len(c.ClientCertPEM) > 0 && len(c.ClientKeyPEM) > 0 {
		pair, err := tls.X509KeyPair(c.ClientCertPEM, c.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("加载客户端证书: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}
