package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// TestSafestDemo 跑通最安全用法的完整正向流程(含分级=pinned_clientcert_basic + 隧道回环)。
func TestSafestDemo(t *testing.T) {
	if err := demo(io.Discard); err != nil {
		t.Fatalf("最安全用法 demo 应成功, 得: %v", err)
	}
}

// TestProbe 验证 probe 子命令核心:经网关访问一个目标,原样拿回 HTTP 响应字节。
func TestProbe(t *testing.T) {
	gwCert, gwKey, err := hgmHttpsProxyServer.GenServerCert("gw", nil, []string{"127.0.0.1"}, 825)
	if err != nil {
		t.Fatal(err)
	}
	serverPin, _ := hgmHttpsProxyClient.SPKIPinFromCertPEM(gwCert)

	const body = "probe-ok-12345"
	targetAddr, stopTarget, err := startRawHTTPTarget(body)
	if err != nil {
		t.Fatal(err)
	}
	defer stopTarget()

	server, err := startGateway(hgmHttpsProxyServer.ServerConfig{
		Listen:          "127.0.0.1:0",
		TLSCertPEM:      gwCert,
		TLSKeyPEM:       gwKey,
		AcceptedBasic:   map[string]string{"u": "p"},
		TargetAllowlist: []string{targetAddr},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	fwd := fmt.Sprintf("https://u:p@%s?serverPins=%s", server.Addr(), serverPin)
	cfg, err := hgmHttpsProxyClient.ParseForwardURL(fwd)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := hgmHttpsProxyClient.Probe(cfg, "http://"+targetAddr+"/", &buf); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "HTTP/1.1 200") || !strings.Contains(got, body) {
		t.Fatalf("probe 未原样拿到响应, 得: %q", got)
	}
}

// startRawHTTPTarget 起一个极简「HTTP」目标:读掉请求(不解析),回一段固定响应即关。
func startRawHTTPTarget(body string) (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(make([]byte, 1024)) // 读掉请求行+头,不解析
				resp := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) +
					"\r\nConnection: close\r\n\r\n" + body
				_, _ = io.WriteString(c, resp)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

// TestSafestRejectsWrongClientCA 第二因子验证:客户端持「另一个 CA」签的证书,
// 即使账号密码/serverPins 全对,也应在 双向 TLS 阶段被网关 fail-closed 拒掉。
func TestSafestRejectsWrongClientCA(t *testing.T) {
	gwCert, gwKey, err := hgmHttpsProxyServer.GenServerCert("gw", nil, []string{"127.0.0.1"}, 825)
	if err != nil {
		t.Fatal(err)
	}
	serverPin, _ := hgmHttpsProxyClient.SPKIPinFromCertPEM(gwCert)

	// 网关信任的 CA(caGood),以及攻击者另起的 CA(caEvil)。
	caGoodCert, _, err := hgmHttpsProxyClient.GenClientCA("ca-good", 3650)
	if err != nil {
		t.Fatal(err)
	}
	goodPin, _ := hgmHttpsProxyClient.SPKIPinFromCertPEM(caGoodCert)

	caEvilCert, caEvilKey, err := hgmHttpsProxyClient.GenClientCA("ca-evil", 3650)
	if err != nil {
		t.Fatal(err)
	}
	evilChain, evilKey, err := hgmHttpsProxyClient.SignClientCert(caEvilCert, caEvilKey, "endpoint-001", 825)
	if err != nil {
		t.Fatal(err)
	}

	echoAddr, stopEcho, err := startEchoTarget()
	if err != nil {
		t.Fatal(err)
	}
	defer stopEcho()

	goodPins, _ := hgmHttpsProxyClient.ParsePins(goodPin) // 网关只认 caGood
	server, err := startGateway(hgmHttpsProxyServer.ServerConfig{
		Listen:        "127.0.0.1:0",
		TLSCertPEM:    gwCert,
		TLSKeyPEM:     gwKey,
		AcceptedBasic: map[string]string{"endpoint-001": "S3cr3t-Pa55"},
		ClientCaPins:  goodPins,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	forwardTo := fmt.Sprintf("https://endpoint-001:S3cr3t-Pa55@%s?serverPins=%s&clientCaPins=%s",
		server.Addr(), serverPin, goodPin)
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(forwardTo)
	cfg.ClientCertPEM, cfg.ClientKeyPEM = evilChain, evilKey // 偷了 URL,但证书是 caEvil 签的

	_, err = cfg.Dial(echoAddr, nil)
	if err == nil {
		t.Fatal("错误 CA 的客户端竟连上了, 双向 TLS 第二因子失效")
	}
	// TLS1.3 下客户端 Handshake() 在服务端校验其证书前即返回,故 fail-closed 以
	// "tls: bad certificate" 告警形式在随后读 CONNECT 响应时浮现。
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("期望 双向 TLS 因证书被拒, 得: %v", err)
	}
}
