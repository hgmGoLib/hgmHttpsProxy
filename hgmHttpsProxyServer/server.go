// Package hgmHttpsProxyServer 出口代理网关侧:接受外层 TLS + 内层 CONNECT,校验
// clientCaPins(双向 TLS)/ Basic / 来源 CIDR / 目标白名单,通过后建立隧道双向转发。
//
// 共享的协议/pin/Basic 代码都在 hgmHttpsProxyClient(按项目约定:共享代码写在客户端包),
// 服务端 import 它复用,不另开 proto 包。
package hgmHttpsProxyServer

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
)

// DefaultRelayIdleTimeout 隧道空闲超时默认值:两个方向连续这么久都没有字节流动就断开。
const DefaultRelayIdleTimeout = 2 * time.Minute

// ServerConfig 网关配置。
type ServerConfig struct {
	Listen          string            // 如 ":9443"
	TLSCertPEM      []byte            // 服务端证书 PEM(与 Key 同时为空 = 明文 listen,仅 demo/内网)
	TLSKeyPEM       []byte            // 服务端私钥 PEM
	AcceptedBasic   map[string]string // user → pass(空 = 不要求账号密码)
	ClientCaPins    []hgmHttpsProxyClient.Pin         // 客户端上一级 CA 的 SPKI pin(空 = 不要求客户端证书)
	AllowedCIDRs    []string          // 允许来源网段(空 = 不限)
	TargetAllowlist []string          // 允许 CONNECT 的目标 host:port(空 = 不限)

	// OnAudit 可选审计回调(注入点:lib 不依赖任何具体审计/通知实现)。
	OnAudit func(AuditEvent)

	// DialUpstream 可选:自定义到 CONNECT 目标的「下一跳」拨号(注入点:区域选路 /
	// 链式上游代理 / 自定义 DNS 解析)。nil = 默认 net.Dialer 直连 target。
	// ctx 在拨号阶段带 10s 超时;target 为 CONNECT 请求里的 host:port。
	DialUpstream func(ctx context.Context, target string) (net.Conn, error)

	// RelayIdleTimeout 隧道空闲超时:两个方向连续这么久都没有任何字节流动就断开隧道。
	// 0 = 用默认 2 分钟(DefaultRelayIdleTimeout);负数 = 永不超时(长连接/流式场景)。
	RelayIdleTimeout time.Duration

	// FailureReasonHeader 拒绝/失败响应里写失败原因(cidr_denied/auth_failed/...)的头名,
	// 便于对接方在响应侧诊断。空 = 默认 "X-Hp-Failure-Reason"。
	FailureReasonHeader string
}

// DefaultFailureReasonHeader 拒绝响应里失败原因头的默认名。
const DefaultFailureReasonHeader = "X-Hp-Failure-Reason"

// AuditEvent 一次连接的审计记录。
//
// 一条隧道会产生两条 200 事件:建立时(Reason="")与结束时(Reason="closed")。
// 结束事件才带 BytesToTarget/BytesToClient/Duration(计量、对账、长连接审计用)。
type AuditEvent struct {
	RemoteAddr string
	User       string
	Target     string
	Status     int
	Reason     string

	// 仅隧道结束事件(Reason="closed")有意义:
	BytesToTarget int64         // 客户端→目标 累计字节
	BytesToClient int64         // 目标→客户端 累计字节
	Duration      time.Duration // 隧道从建立到关闭的时长
}

// Server 网关服务。
type Server struct {
	cfg    ServerConfig
	mu     sync.Mutex
	ln     net.Listener
	closed bool
	conns  map[net.Conn]struct{} // 在飞连接集合(供 Shutdown 强关),mu 保护
	wg     sync.WaitGroup        // 跟踪在飞 handleConn(供 Shutdown 排空)
}

// NewServer 校验配置并构造 Server(尚未监听,Serve 才开始)。
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("ServerConfig.Listen 为空")
	}
	if len(cfg.TLSCertPEM) > 0 || len(cfg.TLSKeyPEM) > 0 {
		if len(cfg.TLSCertPEM) == 0 || len(cfg.TLSKeyPEM) == 0 {
			return nil, errors.New("TLSCertPEM / TLSKeyPEM 必须同时提供")
		}
	}
	if len(cfg.ClientCaPins) > 0 && len(cfg.TLSCertPEM) == 0 {
		return nil, errors.New("clientCaPins 需要 TLS(明文 listen 无法做 双向 TLS)")
	}
	for u := range cfg.AcceptedBasic {
		if u == "" {
			return nil, errors.New("AcceptedBasic 含空 user")
		}
	}
	if cfg.RelayIdleTimeout == 0 {
		cfg.RelayIdleTimeout = DefaultRelayIdleTimeout
	}
	if cfg.FailureReasonHeader == "" {
		cfg.FailureReasonHeader = DefaultFailureReasonHeader
	}
	return &Server{cfg: cfg, conns: make(map[net.Conn]struct{})}, nil
}

// Listen 提前绑定监听端口(可选)。Serve 会自动调用它,但提前调用能让对接方在 Serve 之前
// 就拿到 Addr(),并把「端口被占用」这类错误在启动阶段同步暴露(而不是埋在 Serve 的 goroutine 里)。
// 重复调用幂等;已 Close/Shutdown 后调用返回错误。
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return nil
	}
	if s.closed {
		return errors.New("hgmHttpsProxy: server 已 Close/Shutdown,不能再 Listen")
	}
	ln, err := s.buildListener()
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve 阻塞运行,直到 Close 或致命错误。
func (s *Server) Serve() error {
	if err := s.Listen(); err != nil {
		return err
	}
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.mu.Lock()
		if s.closed { // Accept 与 Close/Shutdown 的竞争窗口:已停服就别再处理
			s.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

// Addr 返回实际监听地址(Serve 后才有值;用于测试拿随机端口)。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// ForwardURL 基于当前运行配置拼出一条「客户端可直接用」的 forward_to URL:
//
//	scheme://user:pass@host:port?serverPins=...&clientCaPins=...
//
// 只声明「连这台网关实际需要的东西」:有 TLS → https 且带 serverPins(实时算服务端证书 SPKI);
// 有 AcceptedBasic → 带 user:pass(多账号时取排序最小的一条,够示范即可);有 ClientCaPins →
// 带 clientCaPins(客户端还需另行注入证书,URL 只表达这个要求)。host 为展示用主机名/IP
// (空 = 127.0.0.1,调用者自行换成真实可达地址);端口取实际监听端口。Listen/Serve 后才有意义。
func (s *Server) ForwardURL(host string) (string, error) {
	scheme := "http"
	if len(s.cfg.TLSCertPEM) > 0 {
		scheme = "https"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port := s.Addr()
	if _, p, err := net.SplitHostPort(port); err == nil {
		port = p
	}
	var userinfo string
	if len(s.cfg.AcceptedBasic) > 0 {
		users := make([]string, 0, len(s.cfg.AcceptedBasic))
		for u := range s.cfg.AcceptedBasic {
			users = append(users, u)
		}
		sort.Strings(users) // map 无序:取排序最小的一条,保证每次输出稳定
		u := users[0]
		userinfo = url.UserPassword(u, s.cfg.AcceptedBasic[u]).String() + "@"
	}
	out := fmt.Sprintf("%s://%s%s:%s", scheme, userinfo, host, port)

	// query:pin 形如 sha256:base64url,冒号/逗号在 query 里合法且客户端按原样解析,故不再转义。
	var q []string
	if len(s.cfg.TLSCertPEM) > 0 {
		pin, err := hgmHttpsProxyClient.SPKIPinFromCertPEM(s.cfg.TLSCertPEM)
		if err != nil {
			return "", fmt.Errorf("算 serverPins: %w", err)
		}
		q = append(q, "serverPins="+pin)
	}
	if len(s.cfg.ClientCaPins) > 0 {
		pins := make([]string, 0, len(s.cfg.ClientCaPins))
		for _, p := range s.cfg.ClientCaPins {
			pins = append(pins, p.String())
		}
		q = append(q, "clientCaPins="+strings.Join(pins, ","))
	}
	if len(q) > 0 {
		out += "?" + strings.Join(q, "&")
	}
	return out, nil
}

// Close 立即停止监听并返回,不等待在飞隧道(也不强关它们,任其自然跑完或被各自超时收掉)。
// 想「停止接受新连接 + 排空在飞隧道」用 Shutdown。
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

// Shutdown 优雅停服:先停止接受新连接,再等所有在飞隧道最多 timeout 自然结束;到点仍未
// 结束的隧道被强制关闭。用于滚动发布,避免硬断连接。
//   - timeout > 0:timeout 内全部自然排空 → 返回 nil;超时 → 强关剩余隧道并返回错误。
//   - timeout <= 0:不等待,立即强关所有在飞隧道(等强关收尾后返回 nil)。
func (s *Server) Shutdown(timeout time.Duration) error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close() // 停止 accept
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()

	if timeout > 0 {
		select {
		case <-done:
			return nil // 在 timeout 内干净排空
		case <-time.After(timeout):
			// 超时,落到下面强关
		}
	}
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close() // 强关在飞隧道 → relay 读写出错 → handleConn 收尾
	}
	s.mu.Unlock()
	<-done
	if timeout > 0 {
		return fmt.Errorf("hgmHttpsProxy: 优雅停服超时(%s),已强制关闭剩余在飞隧道", timeout)
	}
	return nil
}

// connDone 在 handleConn 收尾时调用:把连接移出在飞集合并让 wg 计数减一(供 Shutdown 排空)。
func (s *Server) connDone(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	s.wg.Done()
}

func (s *Server) buildListener() (net.Listener, error) {
	tcp, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	if len(s.cfg.TLSCertPEM) == 0 {
		return tcp, nil // 明文(demo/内网)
	}
	pair, err := tls.X509KeyPair(s.cfg.TLSCertPEM, s.cfg.TLSKeyPEM)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("加载服务端证书: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}
	if len(s.cfg.ClientCaPins) > 0 {
		pins := s.cfg.ClientCaPins
		tlsCfg.ClientAuth = tls.RequireAnyClientCert // 自己用 pin 校验,不用 ClientCAs 池
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyClientCaPins(rawCerts, pins)
		}
	}
	return tls.NewListener(tcp, tlsCfg), nil
}

// verifyClientCaPins 校验客户端「叶子 + 上一级 CA」两级链:CA(rawCerts[1])SPKI 命中 pin,
// 且叶子确由该 CA 签发。只支持 2 级。fail-closed。pin 的 CA 必须是真 CA 证书(BasicConstraints CA:TRUE)。
func verifyClientCaPins(rawCerts [][]byte, pins []hgmHttpsProxyClient.Pin) error {
	if len(rawCerts) < 2 {
		return errors.New("客户端未提供 叶子+CA 两级证书")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("解析客户端叶子证书: %w", err)
	}
	ca, err := x509.ParseCertificate(rawCerts[1])
	if err != nil {
		return fmt.Errorf("解析客户端 CA 证书: %w", err)
	}
	if !hgmHttpsProxyClient.MatchSPKIPin(pins, ca) {
		return errors.New("客户端 CA clientCaPins 不匹配(fail-closed)")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("客户端叶子证书非该 CA 签发: %w", err)
	}
	return nil
}

func (s *Server) handleConn(raw net.Conn) {
	defer s.connDone(raw) // 注册 LIFO 在前 → 实际后于 raw.Close 执行(先关连接,再 wg.Done)
	defer raw.Close()
	remote := raw.RemoteAddr().String()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second)) // 握手+CONNECT 阶段超时

	// 显式触发 TLS 握手,以便 clientCaPins 不符的连接尽早被拒(并能审计握手失败)。
	if tc, ok := raw.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			s.audit(AuditEvent{RemoteAddr: remote, Status: 0, Reason: "tls_handshake_failed:" + err.Error()})
			return
		}
	}

	br := bufio.NewReader(raw)
	req, err := hgmHttpsProxyClient.ReadConnectRequest(br)
	if err != nil {
		_ = hgmHttpsProxyClient.WriteConnectResponse(raw, 400, "Bad Request", nil)
		s.audit(AuditEvent{RemoteAddr: remote, Status: 400, Reason: "bad_connect:" + err.Error()})
		return
	}

	status, reason, user := s.authorize(req, remote)
	if status != 200 {
		extra := map[string]string{s.cfg.FailureReasonHeader: reason}
		if status == 407 {
			extra[hgmHttpsProxyClient.HeaderProxyAuthenticate] = `Basic realm="hgmHttpsProxy"`
		}
		_ = hgmHttpsProxyClient.WriteConnectResponse(raw, status, reasonPhrase(status), extra)
		s.audit(AuditEvent{RemoteAddr: remote, User: user, Target: req.Target, Status: status, Reason: reason})
		return
	}

	dialUpstream := s.cfg.DialUpstream
	if dialUpstream == nil {
		dialUpstream = func(ctx context.Context, target string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		}
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstream, err := dialUpstream(dialCtx, req.Target)
	cancel()
	if err != nil {
		_ = hgmHttpsProxyClient.WriteConnectResponse(raw, 502, "Bad Gateway", map[string]string{s.cfg.FailureReasonHeader: "upstream_unreachable"})
		s.audit(AuditEvent{RemoteAddr: remote, User: user, Target: req.Target, Status: 502, Reason: "upstream_unreachable"})
		return
	}
	defer upstream.Close()

	if err := hgmHttpsProxyClient.WriteConnectResponse(raw, 200, "Connection Established", nil); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{}) // 隧道建立,清握手期超时;空闲由 relay 的 idle timer 接管
	s.audit(AuditEvent{RemoteAddr: remote, User: user, Target: req.Target, Status: 200})
	idle := s.cfg.RelayIdleTimeout
	if idle < 0 {
		idle = 0 // 负数 = 永不超时
	}
	start := time.Now()
	toTarget, toClient := relay(raw, br, upstream, idle)
	s.audit(AuditEvent{
		RemoteAddr: remote, User: user, Target: req.Target, Status: 200, Reason: "closed",
		BytesToTarget: toTarget, BytesToClient: toClient, Duration: time.Since(start),
	})
}

// authorize 依次校验 CIDR → Basic → 目标白名单,返回 (status, reason, user)。
func (s *Server) authorize(req *hgmHttpsProxyClient.ConnectRequest, remote string) (status int, reason, user string) {
	if !cidrAllowed(s.cfg.AllowedCIDRs, remote) {
		return 403, "cidr_denied", ""
	}
	if len(s.cfg.AcceptedBasic) > 0 {
		auth := req.Header(hgmHttpsProxyClient.HeaderProxyAuthorization)
		if auth == "" {
			return 407, "missing_auth", ""
		}
		u, p, ok := hgmHttpsProxyClient.ParseBasicAuth(auth)
		if !ok {
			return 403, "auth_failed", ""
		}
		want, exists := s.cfg.AcceptedBasic[u]
		// 无论 user 是否存在都做一次常量时间比对,缓解时序侧信道。
		match := subtle.ConstantTimeCompare([]byte(p), []byte(want)) == 1
		if !exists || !match {
			return 403, "auth_failed", u
		}
		user = u
	}
	if !targetAllowed(s.cfg.TargetAllowlist, req.Target) {
		return 403, "target_denied", user
	}
	return 200, "", user
}

func (s *Server) audit(ev AuditEvent) {
	if s.cfg.OnAudit != nil {
		s.cfg.OnAudit(ev)
	}
}

func cidrAllowed(cidrs []string, remoteAddr string) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func targetAllowed(list []string, target string) bool {
	if len(list) == 0 {
		return true
	}
	for _, t := range list {
		if strings.EqualFold(strings.TrimSpace(t), target) {
			return true
		}
	}
	return false
}

func reasonPhrase(status int) string {
	switch status {
	case 200:
		return "Connection Established"
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 407:
		return "Proxy Authentication Required"
	case 502:
		return "Bad Gateway"
	default:
		return "Error"
	}
}

// relay 双向转发:clientReader 用 bufio.Reader(含 CONNECT 后预读字节),写回用裸 client。
// idleTimeout>0 时启用空闲超时:两个方向连续这么久都没有字节流动就关闭隧道。参考
// hgmNet.RwcTwoWayCopy 的做法——用「活动时重置、到点关连接」的定时器,而不是
// SetReadDeadline(client 侧读经过 bufio,且要兼容任意 io.Reader)。任一方向结束即整体关闭。
// 返回两个方向的累计字节数(toTarget=客户端→目标,toClient=目标→客户端),供结束审计计量。
func relay(client net.Conn, clientReader io.Reader, upstream net.Conn, idleTimeout time.Duration) (toTarget, toClient int64) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}

	// 活动时重置的 idle 定时器(到点 closeBoth)。throttle:至多每 throttle 重置一次,避免
	// 高吞吐下每读一块都 Reset;为补偿这点抖动,定时器实际设为 idleTimeout+throttle。
	var (
		timerMu sync.Mutex
		timer   *time.Timer
	)
	throttle := time.Second
	if idleTimeout > 0 {
		if d := idleTimeout / 10; d > 0 && d < throttle {
			throttle = d
		}
		timer = time.AfterFunc(idleTimeout+throttle, closeBoth)
		defer timer.Stop()
	}

	copyOneWay := func(dst io.Writer, src io.Reader) int64 {
		buf := make([]byte, 32*1024)
		var total int64
		var lastReset time.Time
		for {
			if timer != nil {
				if now := time.Now(); lastReset.IsZero() || now.Sub(lastReset) >= throttle {
					lastReset = now
					timerMu.Lock()
					timer.Reset(idleTimeout + throttle)
					timerMu.Unlock()
				}
			}
			n, rerr := src.Read(buf)
			if n > 0 {
				total += int64(n)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		closeBoth()
		return total
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); toTarget = copyOneWay(upstream, clientReader) }()
	go func() { defer wg.Done(); toClient = copyOneWay(client, upstream) }()
	wg.Wait()
	return
}
