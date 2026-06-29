package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// cmdServe 读 JSON 配置启动网关。参数:-Config=server.json。
//
// JSON 配置类型 hgmHttpsProxyServer.ServerFileConfig 现在放在 server 库里并导出(方便上层
// 代码直接远程下发这份 JSON);证书解析、自签生成、文件首启落盘都在 ToServerConfig 里完成。
func cmdServe(args []string) error {
	path := argStr(args, "Config", "")
	if path == "" {
		return errors.New("serve 需要 -Config=<server.json>")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读配置 %s: %w", path, err)
	}
	var fc hgmHttpsProxyServer.ServerFileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return fmt.Errorf("解析配置 JSON: %w", err)
	}

	cfg, err := fc.ToServerConfig()
	if err != nil {
		return err
	}
	cfg.OnAudit = func(ev hgmHttpsProxyServer.AuditEvent) {
		log.Printf("[audit] remote=%s user=%s target=%s status=%d reason=%s up=%d down=%d dur=%s",
			ev.RemoteAddr, ev.User, ev.Target, ev.Status, ev.Reason, ev.BytesToTarget, ev.BytesToClient, ev.Duration)
	}

	s, err := hgmHttpsProxyServer.NewServer(cfg)
	if err != nil {
		return err
	}
	// 先 Listen 绑定端口:端口占用等错误在此同步暴露,且 Addr() 立即可用于打印实际 URL。
	if err := s.Listen(); err != nil {
		return err
	}
	log.Printf("hgmHttpsProxyServer 监听 %s (tls=%v clientCaPins=%d basicUsers=%d targets=%d)",
		cfg.Listen, len(cfg.TLSCertPEM) > 0, len(cfg.ClientCaPins), len(cfg.AcceptedBasic), len(cfg.TargetAllowlist))
	fmt.Println(listenURL(&fc, s.Addr(), len(cfg.TLSCertPEM) > 0))

	// 异步跑 Serve,主协程等 Ctrl+C / SIGTERM,收到即优雅停服。
	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve() }()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh: // Serve 自己挂了(致命错误)
		return err
	case sig := <-sigCh:
		log.Printf("收到信号 %s,正在关闭网关...", sig)
		if err := s.Shutdown(10 * time.Second); err != nil {
			log.Printf("关闭网关: %v", err)
		}
		<-errCh // 等 Serve 退出
		return nil
	}
}

// listenURL 拼出打印给人看的监听 URL。host 用配置里的 DisplayIP(空则 127.0.0.1,让调用者
// 自己想办法找到真实可达地址再改);port 取实际监听端口(Addr 形如 [::]:9443 / 0.0.0.0:9443)。
func listenURL(fc *hgmHttpsProxyServer.ServerFileConfig, addr string, tls bool) string {
	scheme := "http"
	if tls {
		scheme = "https"
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
