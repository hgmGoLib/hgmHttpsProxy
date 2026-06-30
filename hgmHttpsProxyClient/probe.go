package hgmHttpsProxyClient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Probe 经 cfg 指定的代理拨号到 targetURL,发一条最简 GET,把目标返回的原始字节原样写到 out。
// 不解析 HTTP —— 拿到什么字节就写什么字节,纯粹用于「这条代理能不能把我送到目标」的连通性测试。
// https 目标对其自身做标准证书校验(真实站点真实证书);代理外层是否校验由 cfg 的 serverPins
// 决定,两层互不影响。
func Probe(cfg *ClientConfig, targetURL string, out io.Writer) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("解析目标 URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("目标 URL scheme 必须 http/https,收到 %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("目标 URL 缺 host")
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// 经代理建到目标 host:port 的隧道。
	dr := cfg.Dial(DialReq{Target: net.JoinHostPort(host, port)})
	if dr.Err != nil {
		return fmt.Errorf("经代理拨号目标失败: %w", dr.Err)
	}
	conn := dr.Conn
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// https 目标:在隧道上对目标自身做标准 TLS(校验目标真实证书)。
	var rw io.ReadWriter = conn
	if scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("目标 TLS 握手失败: %w", err)
		}
		rw = tc
	}

	// 写一条最简单的 HTTP/1.1 GET(Connection: close 让对端读完即关,便于 dump 结束)。
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(rw, req); err != nil {
		return fmt.Errorf("写请求: %w", err)
	}
	// 原始响应字节原样输出,不解析。
	if _, err := io.Copy(out, rw); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("读响应: %w", err)
	}
	return nil
}
