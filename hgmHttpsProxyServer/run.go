package hgmHttpsProxyServer

import (
	"fmt"
	"log"
)

// RunFileConfigAsyncSimple 简单版:吃一份文件态配置,解析 + 挂一个把审计打到 log 的默认
// OnAudit + RunAsync,把「ToServerConfig→设审计→构造→绑定→后台跑」整串收成一行。前台
// runner / serve 命令直接用;要自定义审计就走 RunAsync(cfg) 自己设 OnAudit。出错即 panic。
//
// 绑定成功后向 stdout 打印一条「客户端可直接用」的 forward_to URL(账号密码/serverPins/
// clientCaPins 都按当前实际配置带上)。放在这里而不是各调用方,保证 serve 子命令与前台 runner
// 等所有入口都拿得到、不会某个入口漏打。DisplayIP 只决定 URL 里的主机名(空 = 127.0.0.1)。
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
	u, err := s.ForwardURL(fc.DisplayIP)
	if err != nil {
		panic(err)
	}
	fmt.Println(u)
	go func() {
		if err := s.Serve(); err != nil {
			panic(err)
		}
	}()
	return s
}
