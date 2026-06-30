// hgmHttpsProxyServer/dialupstream.go — 可选的 SSRF 防护 DialUpstream helper。
//
// readme「限制与部署加固」指出:TargetAllowlist 空时已认证端点可经网关 CONNECT 到内网 /
// 云 metadata,是真实横向移动面。本 helper 提供一个现成的「下一跳」拨号器:解析目标 host→IP,
// 任一要拨的 IP 命中内网/危险网段即拒绝(防域名指向内网绕过),否则拨第一个放行的 IP。
//
// 这张默认表是任何出口代理都一字不差会写的同一张(回环/RFC1918/metadata/CGNAT/ULA),属
// 「通用正确实现」而非「租户策略」,故收进库;但 NewServer 默认仍 DialUpstream=nil(直连),
// 是否启用由集成方显式 cfg.DialUpstream = BlockInternalDialUpstream() 决定,库不偷改默认行为。
package hgmHttpsProxyServer

import (
	"context"
	"fmt"
	"net"
)

// DefaultBlockedTargetCIDRs SSRF 默认屏蔽的目标网段(解析目标 host→IP 后逐个比对)。
var DefaultBlockedTargetCIDRs = []string{
	"127.0.0.0/8",    // 回环
	"::1/128",        // 回环 v6
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"169.254.0.0/16", // link-local(含云 metadata 169.254.169.254)
	"fe80::/10",      // link-local v6
	"100.64.0.0/10",  // CGNAT
	"fc00::/7",       // ULA v6
	"0.0.0.0/8",      // 未指定/本网
	"::/128",         // 未指定 v6
}

// BlockInternalDialUpstream 返回一个 DialUpstream(可直接赋给 ServerConfig.DialUpstream):
// 解析目标 host→IP,任一要拨的 IP 命中 denylist 即拒(防域名指向内网绕过),否则拨第一个放行的 IP。
// denylist = DefaultBlockedTargetCIDRs ∪ extraCIDRs;任一 extraCIDR 非法即返回 error(默认表恒合法,
// 不传 extra 时 error 恒为 nil)。
func BlockInternalDialUpstream(extraCIDRs ...string) (func(ctx context.Context, target string) (net.Conn, error), error) {
	nets := make([]*net.IPNet, 0, len(DefaultBlockedTargetCIDRs)+len(extraCIDRs))
	for _, c := range append(append([]string{}, DefaultBlockedTargetCIDRs...), extraCIDRs...) {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("BlockInternalDialUpstream: 非法 CIDR %q: %w", c, err)
		}
		nets = append(nets, n)
	}
	blocked := func(ip net.IP) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	// 用 ctx(库在拨号阶段带 deadline)做 DNS 解析与拨号,跟随取消/截止时间。
	return func(ctx context.Context, target string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, fmt.Errorf("BlockInternalDialUpstream: 目标 %q 非 host:port: %w", target, err)
		}
		// host 是 IP 字面量:直接比对,不解析。
		if ip := net.ParseIP(host); ip != nil {
			if blocked(ip) {
				return nil, fmt.Errorf("BlockInternalDialUpstream: 目标 IP %s 命中内网/危险网段,拒绝出口", ip)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		}
		// host 是域名:解析后逐个比对,拨第一个放行的 IP。
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("BlockInternalDialUpstream: 解析目标 %s 失败: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("BlockInternalDialUpstream: 目标 %s 无解析结果", host)
		}
		var d net.Dialer
		var lastErr error
		for _, ia := range ips {
			if blocked(ia.IP) {
				lastErr = fmt.Errorf("BlockInternalDialUpstream: 目标 %s 解析到内网/危险 IP %s,拒绝出口", host, ia.IP)
				continue
			}
			conn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(ia.IP.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		return nil, lastErr
	}, nil
}
