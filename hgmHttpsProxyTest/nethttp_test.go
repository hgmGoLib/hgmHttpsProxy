package hgmHttpsProxyTest

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// 与 net/http 的协议兼容性。本库运行时刻意不依赖 net/http(手写 CONNECT),这里用 net/http
// 从两个方向反证线协议互通。

// TestNetHTTP_A_StdClientThroughOurServer:net/http 当「代理客户端」,经本库网关 CONNECT
// 到一个 net/http 的 https 目标。证明本库服务端写出的 CONNECT 应答被标准 http.Transport 接受。
//
// 注:目标必须是 https —— net/http 只有访问 https 目标时才对代理发 CONNECT;访问 http 目标
// 会改用 absolute-form GET 直发代理,而本库只支持 CONNECT。
func TestNetHTTP_A_StdClientThroughOurServer(t *testing.T) {
	const want = "ok-from-nethttp-target"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, want)
	}))
	defer target.Close()
	targetAddr := target.Listener.Addr().String()

	cert, key, _ := gwCert(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM:      cert,
		TLSKeyPEM:       key,
		AcceptedBasic:   map[string]string{"u": "p"},
		TargetAllowlist: []string{targetAddr}, // 顺带验证目标白名单对 net/http 流量同样生效
	})

	proxyURL, err := url.Parse("https://u:p@" + gw.Addr())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// 代理外层 TLS 与目标 TLS 都是自签;net/http 不做 SPKI pin,这里只验 CONNECT 线协议
		// 兼容性,故 InsecureSkipVerify。证书校验语义由 combos_test.go 的 serverPins 路径覆盖。
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试:仅验协议兼容
	}}
	defer client.CloseIdleConnections()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("net/http 经本库网关 GET 失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != want {
		t.Fatalf("期望 200 + %q, 得 %d + %q", want, resp.StatusCode, body)
	}
}

// TestNetHTTP_B_OurClientThroughStdProxy:本库客户端经一个 net/http 实现的 CONNECT 代理
// 拨号到回显目标。证明本库客户端发出的 CONNECT 请求被标准 http.Server(Hijack)正确理解。
func TestNetHTTP_B_OurClientThroughStdProxy(t *testing.T) {
	echo := newEcho(t)

	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
			return
		}
		u, p, ok := hgmHttpsProxyClient.ParseBasicAuth(r.Header.Get(hgmHttpsProxyClient.HeaderProxyAuthorization))
		if !ok || u != "u" || p != "p" {
			w.Header().Set(hgmHttpsProxyClient.HeaderProxyAuthenticate, `Basic realm="std"`)
			http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer clientConn.Close()
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer upstream.Close()
		if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, clientConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(clientConn, upstream); done <- struct{}{} }()
		<-done // 任一方向结束即收摊,defer 关两端解开另一向
	}))
	proxy.EnableHTTP2 = false // 强制 HTTP/1.1,Hijack 才可用(也才能处理 CONNECT)
	proxy.StartTLS()
	defer proxy.Close()

	proxyPin := hgmHttpsProxyClient.ComputeSPKIPin(proxy.Certificate())
	cfg, err := hgmHttpsProxyClient.ParseForwardURL(
		"https://u:p@" + proxy.Listener.Addr().String() + "?serverPins=" + url.QueryEscape(proxyPin))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, cfg, echo, "nonce-through-std-proxy")
}

// TestNetHTTP_C_NetHTTPOverOurTunnel:把本库客户端隧道接到 http.Transport.DialContext,
// 让一个标准 http.Client 透明地经本库网关访问 net/http 的(明文 http)目标。
// 证明本库隧道对 net/http 的字节流完全透明(隧道里跑标准 HTTP/1.1)。
func TestNetHTTP_C_NetHTTPOverOurTunnel(t *testing.T) {
	const want = "hello-over-tunnel"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, want)
	}))
	defer target.Close()
	targetAddr := target.Listener.Addr().String()

	cert, key, serverPin := gwCert(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM:      cert,
		TLSKeyPEM:       key,
		AcceptedBasic:   map[string]string{"u": "p"},
		TargetAllowlist: []string{targetAddr},
	})
	cfg, err := hgmHttpsProxyClient.ParseForwardURL("https://u:p@" + gw.Addr() + "?serverPins=" + url.QueryEscape(serverPin))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{
		// 标准 Transport 的「拨号」改走本库出口代理隧道:addr 即目标 host:port。
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: addr})
			return dr.Conn, dr.Err
		},
	}}
	defer client.CloseIdleConnections()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("net/http 经本库隧道 GET 失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != want {
		t.Fatalf("期望 200 + %q, 得 %d + %q", want, resp.StatusCode, body)
	}
}
