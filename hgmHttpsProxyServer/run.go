package hgmHttpsProxyServer

import "log"

// RunAsync 一步把网关跑起来:NewServer + 同步 Listen(端口占用等启动错误立刻 panic 暴露,
// 不埋进后台 goroutine)+ 后台 Serve。返回已在监听的 *Server,调用方可立即用 Addr(),
// 退出时 Close()。后台 Serve 的致命错误直接 panic(正常 Close 后 Serve 返回 nil,不 panic)。
func RunAsync(cfg ServerConfig) *Server {
	s, err := NewServer(cfg)
	if err != nil {
		panic(err)
	}
	if err := s.Listen(); err != nil {
		panic(err)
	}
	go func() {
		if err := s.Serve(); err != nil {
			panic(err)
		}
	}()
	return s
}

// RunFileConfigAsyncSimple 简单版:吃一份文件态配置,解析 + 挂一个把审计打到 log 的默认
// OnAudit + RunAsync,把「ToServerConfig→设审计→构造→绑定→后台跑」整串收成一行。前台
// runner / serve 命令直接用;要自定义审计就走 RunAsync(cfg) 自己设 OnAudit。出错即 panic。
func RunFileConfigAsyncSimple(fc ServerFileConfig) *Server {
	cfg, err := fc.ToServerConfig()
	if err != nil {
		panic(err)
	}
	cfg.OnAudit = func(ev AuditEvent) {
		log.Printf("[audit] remote=%s user=%s target=%s status=%d reason=%s up=%d down=%d dur=%s",
			ev.RemoteAddr, ev.User, ev.Target, ev.Status, ev.Reason, ev.BytesToTarget, ev.BytesToClient, ev.Duration)
	}
	return RunAsync(cfg)
}
