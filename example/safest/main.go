// Command safest 演示 hgmHttpsProxy 的「最安全用法」(安全分级 high = pinned_clientcert_basic)。
//
// 三道护栏叠满:
//   - 外层 https + TLS1.3:链路加密、无降级
//   - serverPins:客户端 pin 网关叶子证书 SPKI → 防主动中间人 / 假网关(自签也安全)
//   - clientCaPins + 双向 TLS:网关 pin 客户端 CA 的 SPKI → 第二因子,光偷走 forward_to URL
//     也连不上,还得有客户端私钥
//   - Basic 账号密码:第一因子
//   - TargetAllowlist:只放行明确目标
//
// 运行(全程内存自签证书 + 回环目标,不联网):
//
//	go run ./example/safest
//
// 正确性由同目录 main_test.go 验证(正向回环成功 + 换错 CA 的客户端被双向 TLS 拒)。
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

func main() {
	if err := demo(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "demo 失败:", err)
		os.Exit(1)
	}
}

// demo 端到端跑一遍最安全配置,过程打到 out,出错返回 error。
func demo(out io.Writer) error {
	// 1) 网关自签证书 → serverPins。本库只 pin 公钥、不验 SAN/host(见 readme「校验语义」),
	//    这里的 127.0.0.1 SAN 只是让证书规整,不参与连通性。
	gwCert, gwKey, err := hgmHttpsProxyServer.GenServerCert("hgmHttpsProxy-gateway", nil, []string{"127.0.0.1"}, 825)
	if err != nil {
		return err
	}
	serverPin, err := hgmHttpsProxyClient.SPKIPinFromCertPEM(gwCert)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "1) 网关证书已生成, serverPins=%s\n", serverPin)

	// 2) 客户端 CA → clientCaPins(网关用它做双向 TLS 校验)。
	caCert, caKey, err := hgmHttpsProxyClient.GenClientCA("hgmHttpsProxy-client-ca", 3650)
	if err != nil {
		return err
	}
	clientCaPin, err := hgmHttpsProxyClient.SPKIPinFromCertPEM(caCert)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "2) 客户端 CA 已生成, clientCaPins=%s\n", clientCaPin)

	// 3) CA 给端点签发客户端证书链(叶子+CA)。
	clientChain, clientKey, err := hgmHttpsProxyClient.SignClientCert(caCert, caKey, "endpoint-001", 825)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "3) 客户端证书链已签发 (endpoint-001)")

	// 4) 真实目标:一个回显服务,代替 api.openai.com:443。
	echoAddr, stopEcho, err := startEchoTarget()
	if err != nil {
		return err
	}
	defer stopEcho()

	// 5) 网关:护栏全开。
	caPins, err := hgmHttpsProxyClient.ParsePins(clientCaPin)
	if err != nil {
		return err
	}
	server, err := startGateway(hgmHttpsProxyServer.ServerConfig{
		Listen:          "127.0.0.1:0",
		TLSCertPEM:      gwCert,
		TLSKeyPEM:       gwKey,
		AcceptedBasic:   map[string]string{"endpoint-001": "S3cr3t-Pa55"},
		ClientCaPins:    caPins,
		AllowedCIDRs:    []string{"127.0.0.0/8"},
		TargetAllowlist: []string{echoAddr},
		OnAudit: func(ev hgmHttpsProxyServer.AuditEvent) {
			fmt.Fprintf(out, "   [audit] user=%s target=%s status=%d %s\n", ev.User, ev.Target, ev.Status, ev.Reason)
		},
	})
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Fprintf(out, "4) 网关已监听 %s (护栏: serverPins + 双向 TLS + Basic + 目标白名单)\n", server.Addr())

	// 6) 端点配置 = forward_to URL + 注入双向 TLS 证书。
	forwardTo := fmt.Sprintf("https://endpoint-001:S3cr3t-Pa55@%s?serverPins=%s&clientCaPins=%s",
		server.Addr(), serverPin, clientCaPin)
	cfg, err := hgmHttpsProxyClient.ParseForwardURL(forwardTo)
	if err != nil {
		return err
	}
	cfg.ClientCertPEM, cfg.ClientKeyPEM = clientChain, clientKey

	lvl := cfg.Security()
	fmt.Fprintf(out, "5) 安全分级 = %s (%s): %s\n", lvl.Level, lvl.Code, lvl.Note)
	if lvl.Code != "pinned_clientcert_basic" {
		return fmt.Errorf("期望最安全分级 pinned_clientcert_basic, 实得 %s", lvl.Code)
	}

	// 7) 经网关拨号到目标 + 回环验证。
	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echoAddr})
	if dr.Err != nil {
		return fmt.Errorf("Dial: %w", dr.Err)
	}
	conn := dr.Conn
	defer conn.Close()

	const msg = "hello-safest"
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("回环数据不符: 得 %q", buf)
	}
	fmt.Fprintf(out, "6) 隧道回环成功: %q\n", msg)
	return nil
}

// startEchoTarget 起一个回显 TCP 服务,作为 CONNECT 的真实目标。
func startEchoTarget() (addr string, stop func(), err error) {
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
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

// startGateway 启动网关并等到拿到监听地址。
func startGateway(cfg hgmHttpsProxyServer.ServerConfig) (*hgmHttpsProxyServer.Server, error) {
	s, err := hgmHttpsProxyServer.NewServer(cfg)
	if err != nil {
		return nil, err
	}
	go func() { _ = s.Serve() }()
	for i := 0; i < 500 && s.Addr() == ""; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if s.Addr() == "" {
		_ = s.Close()
		return nil, errors.New("网关未在预期时间内监听")
	}
	return s, nil
}
