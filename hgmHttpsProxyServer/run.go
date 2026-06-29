package hgmHttpsProxyServer

import (
	"fmt"
	"log"
	"net"
)

// RunFileConfigAsyncSimple 简单版:吃一份文件态配置,解析 + 挂一个把审计打到 log 的默认
// OnAudit + RunAsync,把「ToServerConfig→设审计→构造→绑定→后台跑」整串收成一行。前台
// runner / serve 命令直接用;要自定义审计就走 RunAsync(cfg) 自己设 OnAudit。出错即 panic。
//
// 绑定成功后向 stdout 打印本次监听的实际 URL(放在这里而不是各调用方,保证 serve 子命令与
// 前台 runner 等所有入口都拿得到,不会某个入口漏打)。
func RunFileConfigAsyncSimple(fc ServerFileConfig) *Server {
	cfg, err := fc.ToServerConfig()
	if err != nil {
		panic(err)
	}
	cfg.OnAudit = func(ev AuditEvent) {
		log.Printf("[audit] remote=%s user=%s target=%s status=%d reason=%s up=%d down=%d dur=%s",
			ev.RemoteAddr, ev.User, ev.Target, ev.Status, ev.Reason, ev.BytesToTarget, ev.BytesToClient, ev.Duration)
	}
	s, err := NewServer(cfg)
	if err != nil {
		panic(err)
	}
	if err := s.Listen(); err != nil {
		panic(err)
	}
	fmt.Println(listenURL(fc, s.Addr()))
	go func() {
		if err := s.Serve(); err != nil {
			panic(err)
		}
	}()
	return s
}

// listenURL 拼出打印给人看的监听 URL。scheme 由 UseHttp 决定;host 用 DisplayIP(空则
// 127.0.0.1,让调用者自己想办法找到真实可达地址再改);port 取实际监听端口(Addr 形如
// [::]:9443 / 0.0.0.0:9443)。
func listenURL(fc ServerFileConfig, addr string) string {
	scheme := "https"
	if fc.UseHttp {
		scheme = "http"
	}
	host := fc.DisplayIP
	if host == "" {
		host = "127.0.0.1"
	}
	port := addr
	if _, p, err := net.SplitHostPort(addr); err == nil {
		port = p
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}
