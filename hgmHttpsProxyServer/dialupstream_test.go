package hgmHttpsProxyServer

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestBlockInternalDialUpstream 验证默认 denylist 对内网/云 metadata/回环等危险目标的判定,
// 以及对公网目标的放行。纯离线:blocked 目标在拨号前即被拒(不联网);allowed 目标用已取消
// 的 ctx 让拨号即时失败(不真连公网),只断言它「过了 denylist」(错误里不含命中文案)。
func TestBlockInternalDialUpstream(t *testing.T) {
	du, err := BlockInternalDialUpstream()
	if err != nil {
		t.Fatalf("BlockInternalDialUpstream 默认表不应 err: %v", err)
	}
	const hitMsg = "命中内网/危险网段"

	blocked := []string{
		"169.254.169.254", // 云 metadata(link-local)
		"127.0.0.1",       // 回环
		"::1",             // 回环 v6
		"10.0.0.5",        // RFC1918
		"172.16.5.5",      // RFC1918
		"172.31.255.255",  // RFC1918 边界
		"192.168.1.1",     // RFC1918
		"100.64.0.1",      // CGNAT
		"fe80::1",         // link-local v6
		"fc00::1",         // ULA v6
		"0.0.0.0",         // 未指定
	}
	for _, ip := range blocked {
		conn, derr := du(context.Background(), net.JoinHostPort(ip, "9"))
		if conn != nil {
			_ = conn.Close()
		}
		if derr == nil || !strings.Contains(derr.Error(), hitMsg) {
			t.Errorf("blocked %s:应被 denylist 拒(含 %q),实得 err=%v", ip, hitMsg, derr)
		}
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	allowed := []string{
		"8.8.8.8",     // 公网
		"1.1.1.1",     // 公网
		"104.18.32.7", // 公网(Cloudflare)
		"172.32.0.1",  // 刚出 RFC1918 172.16/12 范围 → 放行
	}
	for _, ip := range allowed {
		conn, derr := du(cancelled, net.JoinHostPort(ip, "9"))
		if conn != nil {
			_ = conn.Close()
		}
		// 过了 denylist 即去拨号;ctx 已取消 → 拨号失败,但错误必不是「命中内网」。
		if derr != nil && strings.Contains(derr.Error(), hitMsg) {
			t.Errorf("allowed %s:不应被 denylist 拒,实得 %v", ip, derr)
		}
	}
}

// TestBlockInternalDialUpstream_BadExtraCIDR 非法 extraCIDR 应返回 error。
func TestBlockInternalDialUpstream_BadExtraCIDR(t *testing.T) {
	if _, err := BlockInternalDialUpstream("not-a-cidr"); err == nil {
		t.Fatal("非法 extraCIDR 应返回 error")
	}
}
