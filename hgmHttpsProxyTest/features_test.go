package hgmHttpsProxyTest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// TestDialContext_Cancelled 已取消的 ctx 应让 DialContext 立刻失败(不傻等 DialTimeout)。
func TestDialContext_Cancelled(t *testing.T) {
	cert, key, pin := gwCert(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 拨号前就取消

	start := time.Now()
	conn, err := cfg.DialContext(ctx, "127.0.0.1:9", nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("已取消的 ctx 竟拨号成功")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("取消未即时生效,用了 %v", time.Since(start))
	}
}

// TestRelayIdleTimeout 隧道空闲超过 RelayIdleTimeout 时,服务端应主动断开。
func TestRelayIdleTimeout(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic:    map[string]string{"u": "p"},
		RelayIdleTimeout: 200 * time.Millisecond, // 可配:这里调到很短便于测试
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))

	conn, err := cfg.Dial(echo, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// 建好隧道后一个字节都不发 → 两个方向都空闲 → 服务端 idle timer 到点关隧道。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // 兜底,远大于 idle
	start := time.Now()
	if _, rerr := conn.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("空闲隧道竟没被服务端关闭")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("空闲超时没及时触发(用了 %v,应约 220ms);若到 3s 则是撞了我们自己的兜底 deadline", elapsed)
	}
}

// TestRelayIdleTimeout_NotKilledWhenActive 有持续流量时不应被 idle 超时误杀。
func TestRelayIdleTimeout_NotKilledWhenActive(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic:    map[string]string{"u": "p"},
		RelayIdleTimeout: 200 * time.Millisecond,
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))
	conn, err := cfg.Dial(echo, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// 每 50ms 来回一次,持续 ~500ms(> idle 200ms);活动应不断重置 idle timer。
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("ping-%d", i))
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, werr := conn.Write(msg); werr != nil {
			t.Fatalf("第 %d 次写隧道失败(疑似被 idle 误杀): %v", i, werr)
		}
		buf := make([]byte, len(msg))
		if _, rerr := readFull(conn, buf); rerr != nil {
			t.Fatalf("第 %d 次读隧道失败(疑似被 idle 误杀): %v", i, rerr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDialUpstream_Callback 自定义下一跳 dialer 应被调用,并拿到 CONNECT 的真实目标;
// 这里把所有目标都改投到回显服务,验证「选路/改投下一跳」可行。
func TestDialUpstream_Callback(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)

	var (
		mu        sync.Mutex
		gotTarget string
	)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
		DialUpstream: func(ctx context.Context, target string) (net.Conn, error) {
			mu.Lock()
			gotTarget = target
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", echo) // 无视 target,统一改投回显服务
		},
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))

	// 目标写一个根本不存在的 host:port,靠 DialUpstream 改投才能通。
	roundTrip(t, cfg, "nonexistent.internal:443", "via-callback")

	mu.Lock()
	got := gotTarget
	mu.Unlock()
	if got != "nonexistent.internal:443" {
		t.Fatalf("DialUpstream 未拿到 CONNECT 真实目标, 得 %q", got)
	}
}

// readFull 读满 buf(隧道上做精确长度回环用)。
func readFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
