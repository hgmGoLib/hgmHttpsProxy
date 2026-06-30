// Package hgmHttpsProxyClient 出口正向代理的客户端 + 客户端/服务端共享代码。
//
// 协议:外层 TLS(https,默认自签)或明文(http)→ 内层 HTTP CONNECT 隧道 → 真实目标。
// 即使被代理流量本身是 http GET 也一律走 CONNECT(简化:只支持 CONNECT 一种内层)。
// 鉴权:浏览器标准 Proxy-Authorization: Basic base64(user:pass)(RFC 7617)。
//
// 本文件:手写的极简 HTTP/1.1 CONNECT 请求/响应读写(刻意不依赖 net/http,减少依赖面)。
package hgmHttpsProxyClient

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// 协议常量。
const (
	MethodConnect = "CONNECT"
	ProtoHTTP11   = "HTTP/1.1"

	// HeaderProxyAuthorization 客户端→服务端的 Basic 认证头。
	HeaderProxyAuthorization = "Proxy-Authorization"
	// HeaderProxyAuthenticate 服务端缺认证时回 407 带的挑战头。
	HeaderProxyAuthenticate = "Proxy-Authenticate"
)

// 防滥用上限(slowloris / 内存)。
const (
	maxLineLen     = 8 * 1024
	maxHeaderCount = 64
)

// ConnectRequest 一条已解析的 CONNECT 请求。
type ConnectRequest struct {
	Target  string            // host:port
	Headers map[string]string // 头,key 统一小写
}

// Header 取头(大小写不敏感)。
func (r *ConnectRequest) Header(name string) string { return r.Headers[strings.ToLower(name)] }

// readLineCRLF 读一行并去掉结尾 \r\n;超过 max 报错。
func readLineCRLF(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimSuffix(sb.String(), "\r"), nil
		}
		if sb.Len() >= max {
			return "", errors.New("hgmHttpsProxy: 行超长")
		}
		sb.WriteByte(b)
	}
}

// readHeaders 读到空行为止,返回 key 小写的头 map。
func readHeaders(br *bufio.Reader) (map[string]string, error) {
	headers := make(map[string]string)
	for i := 0; ; i++ {
		if i > maxHeaderCount {
			return nil, errors.New("hgmHttpsProxy: 头过多")
		}
		line, err := readLineCRLF(br, maxLineLen)
		if err != nil {
			return nil, fmt.Errorf("读头: %w", err)
		}
		if line == "" {
			return headers, nil
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return nil, fmt.Errorf("非法头行: %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		headers[key] = strings.TrimSpace(line[idx+1:])
	}
}

// ReadConnectRequest 服务端用:解析 CONNECT 请求行 + 头。
func ReadConnectRequest(br *bufio.Reader) (*ConnectRequest, error) {
	line, err := readLineCRLF(br, maxLineLen)
	if err != nil {
		return nil, fmt.Errorf("读请求行: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("非法请求行: %q", line)
	}
	method, target, proto := parts[0], parts[1], parts[2]
	if method != MethodConnect {
		return nil, fmt.Errorf("仅支持 CONNECT,收到 %q", method)
	}
	if !strings.HasPrefix(proto, "HTTP/1.") {
		return nil, fmt.Errorf("非法协议版本: %q", proto)
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("非法 CONNECT 目标 %q: %w", target, err)
	}
	headers, err := readHeaders(br)
	if err != nil {
		return nil, err
	}
	return &ConnectRequest{Target: target, Headers: headers}, nil
}

// validHeaderValue 拒绝含 CR/LF 的头值,防注入。
func validHeaderValue(v string) bool { return !strings.ContainsAny(v, "\r\n") }

// WriteConnectRequest 客户端用:写 CONNECT 请求。proxyAuth 空则不写认证头。
func WriteConnectRequest(w io.Writer, target, proxyAuth string) error {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return fmt.Errorf("非法目标 %q: %w", target, err)
	}
	var sb strings.Builder
	sb.WriteString(MethodConnect + " " + target + " " + ProtoHTTP11 + "\r\n")
	sb.WriteString("Host: " + target + "\r\n")
	if proxyAuth != "" {
		if !validHeaderValue(proxyAuth) {
			return errors.New("proxyAuth 含非法字符")
		}
		sb.WriteString(HeaderProxyAuthorization + ": " + proxyAuth + "\r\n")
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// WriteConnectResponse 服务端用:写状态行 + 头 + 空行。
func WriteConnectResponse(w io.Writer, status int, phrase string, extra map[string]string) error {
	var sb strings.Builder
	sb.WriteString(ProtoHTTP11 + " " + strconv.Itoa(status) + " " + phrase + "\r\n")
	for k, v := range extra {
		if validHeaderValue(k) && validHeaderValue(v) {
			sb.WriteString(k + ": " + v + "\r\n")
		}
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// ReadConnectResponseStatus 客户端用:读状态行 + 头,返回状态码与原因短语。
func ReadConnectResponseStatus(br *bufio.Reader) (status int, phrase string, headers map[string]string, err error) {
	line, err := readLineCRLF(br, maxLineLen)
	if err != nil {
		return 0, "", nil, fmt.Errorf("读状态行: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, "", nil, fmt.Errorf("非法状态行: %q", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, "", nil, fmt.Errorf("非法状态码: %q", parts[1])
	}
	if len(parts) == 3 {
		phrase = parts[2]
	}
	headers, err = readHeaders(br)
	if err != nil {
		return 0, "", nil, err
	}
	return code, phrase, headers, nil
}

// BufferedConn 包 net.Conn + bufio.Reader:CONNECT 握手后 bufio 可能已预读了隧道
// 数据字节,直接用裸 conn 会丢这部分,故 Read 走 bufio。
type BufferedConn struct {
	net.Conn
	R *bufio.Reader
}

// Read 走 bufio,消化预读字节后回落底层 conn。
func (c *BufferedConn) Read(p []byte) (int, error) { return c.R.Read(p) }
