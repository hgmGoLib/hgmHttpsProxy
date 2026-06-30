package hgmHttpsProxyServer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
)

// genSelfSigned 生成一张 127.0.0.1 的自签 TLS 证书(测试用,不联网)。
func genSelfSigned(t *testing.T) (certPEM, keyPEM []byte, spkiPin string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-gw"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, hgmHttpsProxyClient.ComputeSPKIPin(cert)
}

// startEcho 起一个回显 TCP 服务,作为 CONNECT 的真实目标。
func startEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func startServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	for i := 0; i < 200 && s.Addr() == ""; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if s.Addr() == "" {
		t.Fatal("server 未在预期时间内监听")
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestE2E_PinnedBasic_RoundTrip 正常路径:serverPins + Basic,数据回环。
func TestE2E_PinnedBasic_RoundTrip(t *testing.T) {
	cert, key, pin := genSelfSigned(t)
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	s := startServer(t, ServerConfig{
		TLSCertPEM:    cert,
		TLSKeyPEM:     key,
		AcceptedBasic: map[string]string{"alice": "s3cret"},
	})

	fwd := fmt.Sprintf("https://alice:s3cret@%s?serverPins=%s", s.Addr(), pin)
	cfg, err := hgmHttpsProxyClient.ParseForwardURL(fwd)
	if err != nil {
		t.Fatal(err)
	}
	if lvl := cfg.Security(); lvl.Code != "pinned_basic" {
		t.Fatalf("安全分级应 pinned_basic,得 %q", lvl.Code)
	}

	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echoAddr})
	if dr.Err != nil {
		t.Fatalf("Dial: %v", dr.Err)
	}
	conn := dr.Conn
	defer conn.Close()

	const msg = "hello-egress-proxy"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("回环数据不符:得 %q", buf)
	}
}

// TestE2E_WrongPassword 错误密码 → 403 auth_failed。
func TestE2E_WrongPassword(t *testing.T) {
	cert, key, pin := genSelfSigned(t)
	s := startServer(t, ServerConfig{
		TLSCertPEM:    cert,
		TLSKeyPEM:     key,
		AcceptedBasic: map[string]string{"alice": "s3cret"},
	})
	fwd := fmt.Sprintf("https://alice:WRONG@%s?serverPins=%s", s.Addr(), pin)
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fwd)
	err := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: "127.0.0.1:1"}).Err
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("期望 403 拒绝,得 %v", err)
	}
}

// TestE2E_PinMismatch serverPins 不符 → TLS 握手 fail-closed。
func TestE2E_PinMismatch(t *testing.T) {
	cert, key, _ := genSelfSigned(t)
	_, _, otherPin := genSelfSigned(t) // 另一张证书的 pin,不匹配
	s := startServer(t, ServerConfig{
		TLSCertPEM:    cert,
		TLSKeyPEM:     key,
		AcceptedBasic: map[string]string{"alice": "s3cret"},
	})
	fwd := fmt.Sprintf("https://alice:s3cret@%s?serverPins=%s", s.Addr(), otherPin)
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fwd)
	err := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: "127.0.0.1:1"}).Err
	if err == nil || !strings.Contains(err.Error(), "握手") {
		t.Fatalf("期望握手因 pin 不符失败,得 %v", err)
	}
}

// TestE2E_MissingAuth 无认证头 → 407。
func TestE2E_MissingAuth(t *testing.T) {
	cert, key, pin := genSelfSigned(t)
	s := startServer(t, ServerConfig{
		TLSCertPEM:    cert,
		TLSKeyPEM:     key,
		AcceptedBasic: map[string]string{"alice": "s3cret"},
	})
	// 不带 userinfo → 不发 Proxy-Authorization
	fwd := fmt.Sprintf("https://%s?serverPins=%s", s.Addr(), pin)
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fwd)
	err := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: "127.0.0.1:1"}).Err
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("期望 407,得 %v", err)
	}
}

// TestE2E_TargetDenied 目标不在白名单 → 403 target_denied。
func TestE2E_TargetDenied(t *testing.T) {
	cert, key, pin := genSelfSigned(t)
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	s := startServer(t, ServerConfig{
		TLSCertPEM:      cert,
		TLSKeyPEM:       key,
		AcceptedBasic:   map[string]string{"alice": "s3cret"},
		TargetAllowlist: []string{"api.openai.com:443"},
	})
	fwd := fmt.Sprintf("https://alice:s3cret@%s?serverPins=%s", s.Addr(), pin)
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fwd)
	err := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echoAddr}).Err
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("期望 403 target_denied,得 %v", err)
	}
}
