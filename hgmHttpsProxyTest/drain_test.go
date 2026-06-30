package hgmHttpsProxyTest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// waitEvent 轮询等到一条 Reason 含 reason 的审计并返回它(auditSink 定义在 reject_test.go)。
func (a *auditSink) waitEvent(t *testing.T, reason string) hgmHttpsProxyServer.AuditEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		for _, ev := range a.evs {
			if strings.Contains(ev.Reason, reason) {
				a.mu.Unlock()
				return ev
			}
		}
		a.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("未等到 Reason 含 %q 的审计", reason)
	return hgmHttpsProxyServer.AuditEvent{}
}

// TestAudit_ConnClosed 隧道结束应产生一条 closed 审计,带正确的双向字节数与时长。
func TestAudit_ConnClosed(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	sink := &auditSink{}
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
		OnAudit:       sink.record,
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))

	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echo})
	if dr.Err != nil {
		t.Fatalf("Dial: %v", dr.Err)
	}
	conn := dr.Conn
	const msg = "audit-bytes-123456"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close() // 结束隧道 → 触发 closed 审计

	ev := sink.waitEvent(t, "closed")
	if ev.BytesToTarget != int64(len(msg)) || ev.BytesToClient != int64(len(msg)) {
		t.Fatalf("字节统计不对: up=%d down=%d, 都应=%d", ev.BytesToTarget, ev.BytesToClient, len(msg))
	}
	if ev.Duration <= 0 {
		t.Fatalf("时长应 >0, 得 %s", ev.Duration)
	}
}

// TestShutdown_DrainsInflight Shutdown 应等在飞隧道自然结束再返回(不硬断)。
func TestShutdown_DrainsInflight(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))
	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echo}) // 一条在飞隧道
	if dr.Err != nil {
		t.Fatalf("Dial: %v", dr.Err)
	}
	conn := dr.Conn

	shutErr := make(chan error, 1)
	go func() { shutErr <- gw.Shutdown(3 * time.Second) }()

	time.Sleep(150 * time.Millisecond) // 让 Shutdown 先停 accept 并进入等待
	select {
	case e := <-shutErr:
		t.Fatalf("Shutdown 没等在飞隧道就返回了: %v", e)
	default:
	}

	_ = conn.Close() // 结束在飞隧道,Shutdown 应随即干净返回
	select {
	case e := <-shutErr:
		if e != nil {
			t.Fatalf("自然排空应返回 nil, 得 %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("关连接后 Shutdown 未及时排空返回")
	}
}

// TestShutdown_TimeoutForceCloses 在飞隧道不肯结束时,Shutdown 到点强关并返回错误。
func TestShutdown_TimeoutForceCloses(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic:    map[string]string{"u": "p"},
		RelayIdleTimeout: time.Minute, // 调大,确保隧道不会自己 idle 关,逼 Shutdown 走强关
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))
	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echo})
	if dr.Err != nil {
		t.Fatalf("Dial: %v", dr.Err)
	}
	conn := dr.Conn
	defer conn.Close()

	start := time.Now()
	err := gw.Shutdown(300 * time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("空闲在飞隧道应触发超时强关并返回错误")
	}
	if elapsed < 250*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("应在 timeout(300ms)附近返回, 实际 %v", elapsed)
	}
	// 在飞隧道应已被强制关闭:client 读很快出错。
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := conn.Read(make([]byte, 1)); e == nil {
		t.Fatal("在飞隧道未被强制关闭")
	}
}

// TestClose_Immediate Close 立即返回(不等在飞),且之后不再接受新连接。
func TestClose_Immediate(t *testing.T) {
	cert, key, pin := gwCert(t)
	echo := newEcho(t)
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic:    map[string]string{"u": "p"},
		RelayIdleTimeout: time.Minute,
	})
	cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), pin))
	dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echo}) // 一条在飞隧道,Close 不应被它拖住
	if dr.Err != nil {
		t.Fatalf("Dial: %v", dr.Err)
	}
	conn := dr.Conn
	defer conn.Close()

	start := time.Now()
	if err := gw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("Close 应立即返回(不等在飞),用了 %v", time.Since(start))
	}
	// listener 已关,新连接应失败。
	if cfg.Dial(hgmHttpsProxyClient.DialReq{Target: echo}).Err == nil {
		t.Fatal("Close 后仍能新建连接")
	}
}
