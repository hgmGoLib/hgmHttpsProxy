package hgmHttpsProxyTest

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// 复用产品库自己的证书生成函数当夹具,顺带也覆盖了 GenServerCert / GenClientCA / SignClientCert。

// gwCert 生成一张网关自签证书,返回 cert/key PEM 与其 serverPins。
func gwCert(t *testing.T) (certPEM, keyPEM []byte, serverPin string) {
	t.Helper()
	certPEM, keyPEM, err := hgmHttpsProxyServer.GenServerCert("test-gateway", nil, []string{"127.0.0.1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	serverPin, err = hgmHttpsProxyClient.SPKIPinFromCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, serverPin
}

// clientCA 生成一个客户端 CA,返回 CA cert/key PEM 与其 clientCaPins。
func clientCA(t *testing.T, cn string) (caCertPEM, caKeyPEM []byte, caPin string) {
	t.Helper()
	caCertPEM, caKeyPEM, err := hgmHttpsProxyClient.GenClientCA(cn, 1)
	if err != nil {
		t.Fatal(err)
	}
	caPin, err = hgmHttpsProxyClient.SPKIPinFromCertPEM(caCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	return caCertPEM, caKeyPEM, caPin
}

// signClient 用 CA 给端点签发客户端证书链(叶子+CA)。
func signClient(t *testing.T, caCertPEM, caKeyPEM []byte, cn string) (chainPEM, keyPEM []byte) {
	t.Helper()
	chainPEM, keyPEM, err := hgmHttpsProxyClient.SignClientCert(caCertPEM, caKeyPEM, cn, 1)
	if err != nil {
		t.Fatal(err)
	}
	return chainPEM, keyPEM
}

// newGateway 在 127.0.0.1 随机端口起一个网关,等到拿到监听地址,注册 Cleanup 关闭。
func newGateway(t *testing.T, cfg hgmHttpsProxyServer.ServerConfig) *hgmHttpsProxyServer.Server {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	s, err := hgmHttpsProxyServer.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = s.Serve() }()
	for i := 0; i < 500 && s.Addr() == ""; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if s.Addr() == "" {
		t.Fatal("网关未在预期时间内监听")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newEcho 起一个回显 TCP 服务作为 CONNECT 的真实目标,返回其 host:port。
func newEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}

// roundTrip 经 cfg 拨号到回显目标,写入一段 nonce 再读回,断言一致 —— 证明隧道真的通了。
func roundTrip(t *testing.T, cfg *hgmHttpsProxyClient.ClientConfig, echoAddr, nonce string) {
	t.Helper()
	conn, err := cfg.Dial(echoAddr, map[string]string{"X-Endpoint-Id": "test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, nonce); err != nil {
		t.Fatalf("写隧道: %v", err)
	}
	buf := make([]byte, len(nonce))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("读隧道: %v", err)
	}
	if string(buf) != nonce {
		t.Fatalf("回环数据不符: 期望 %q 得 %q", nonce, buf)
	}
}
