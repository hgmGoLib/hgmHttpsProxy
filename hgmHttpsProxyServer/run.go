package hgmHttpsProxyServer

// RunAsync 一步把网关跑起来:NewServer + 同步 Listen(端口占用等启动错误立刻 panic 暴露,
// 不埋进后台 goroutine)+ 后台 Serve。返回已在监听的 *Server,调用方可立即用 Addr(),
// 退出时 Close()/Shutdown()。后台 Serve 的致命错误直接 panic(正常 Close 后 Serve 返回 nil,
// 不 panic)。把「构造→绑定→后台跑」这串样板收成一行,给前台 runner / dev 工具用。
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
