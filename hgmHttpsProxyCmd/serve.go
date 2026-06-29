package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// 简单版:解析+默认审计+后台跑+打印实际监听 URL 都收在 RunFileConfigAsyncSimple 里。
	// 主协程等 Ctrl+C / SIGTERM,收到直接 Close(没有同时拉起新版进程的场景,不必 Shutdown 排空)。
	s := hgmHttpsProxyServer.RunFileConfigAsyncSimple(fc)
	defer s.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("收到信号 %s,正在关闭网关...", sig)
	return nil
}
