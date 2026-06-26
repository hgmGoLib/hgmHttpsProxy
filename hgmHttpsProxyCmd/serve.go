package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// serverFileConfig serve 子命令的 JSON 配置。
//
// 证书/私钥有两组各自含义明确的字段,每个字段只表示一件事(不重载):
//   - 内嵌组:TLSCertPEM / TLSKeyPEM —— 直接放 PEM 文本
//   - 文件组:TLSCertFile / TLSKeyFile —— 放文件路径
//
// 证书与私钥各自在「内嵌」与「文件」里二选一;两组都空 = 明文监听(仅 demo)。
// 不开命令行参数堆,所有配置集中在一个 JSON 文件,部署脚本/审阅都更直观。
type serverFileConfig struct {
	Listen          string            // 如 ":9443"
	TLSCertPEM      string            // 网关证书:内嵌 PEM 文本
	TLSKeyPEM       string            // 网关私钥:内嵌 PEM 文本
	TLSCertFile     string            // 网关证书:文件路径
	TLSKeyFile      string            // 网关私钥:文件路径
	AcceptedBasic   map[string]string // user → pass(空 = 不要求账号密码)
	ClientCaPins    []string          // 客户端上一级 CA 的 SPKI pin(空 = 不要求客户端证书)
	AllowedCIDRs    []string          // 允许来源网段(空 = 不限)
	TargetAllowlist []string          // 允许 CONNECT 的目标 host:port(空 = 不限)

	RelayIdleTimeoutSeconds int // 隧道空闲超时(秒):0 = 默认 2 分钟;负数 = 永不超时
}

// cmdServe 读 JSON 配置启动网关。参数:-Config=server.json。
func cmdServe(args []string) error {
	path := argStr(args, "Config", "")
	if path == "" {
		return errors.New("serve 需要 -Config=<server.json>")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读配置 %s: %w", path, err)
	}
	var fc serverFileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return fmt.Errorf("解析配置 JSON: %w", err)
	}

	cfg := hgmHttpsProxyServer.ServerConfig{
		Listen:          fc.Listen,
		AcceptedBasic:   fc.AcceptedBasic,
		AllowedCIDRs:    fc.AllowedCIDRs,
		TargetAllowlist:  fc.TargetAllowlist,
		RelayIdleTimeout: time.Duration(fc.RelayIdleTimeoutSeconds) * time.Second, // 0 → NewServer 兜底 2 分钟
		OnAudit: func(ev hgmHttpsProxyServer.AuditEvent) {
			log.Printf("[audit] remote=%s user=%s target=%s status=%d reason=%s up=%d down=%d dur=%s",
				ev.RemoteAddr, ev.User, ev.Target, ev.Status, ev.Reason, ev.BytesToTarget, ev.BytesToClient, ev.Duration)
		},
	}
	if cfg.TLSCertPEM, err = pickPEM(fc.TLSCertPEM, fc.TLSCertFile, "TLSCert"); err != nil {
		return err
	}
	if cfg.TLSKeyPEM, err = pickPEM(fc.TLSKeyPEM, fc.TLSKeyFile, "TLSKey"); err != nil {
		return err
	}
	if len(fc.ClientCaPins) > 0 {
		if cfg.ClientCaPins, err = hgmHttpsProxyClient.ParsePins(strings.Join(fc.ClientCaPins, ",")); err != nil {
			return fmt.Errorf("ClientCaPins: %w", err)
		}
	}

	s, err := hgmHttpsProxyServer.NewServer(cfg)
	if err != nil {
		return err
	}
	log.Printf("hgmHttpsProxyServer 监听 %s (tls=%v clientCaPins=%d basicUsers=%d targets=%d)",
		cfg.Listen, len(cfg.TLSCertPEM) > 0, len(cfg.ClientCaPins), len(cfg.AcceptedBasic), len(cfg.TargetAllowlist))
	return s.Serve()
}

// pickPEM 从「内嵌 PEM」与「文件路径」两个字段里取一份 PEM:同名两字段只能填一个,
// 都空返回 nil(交由 NewServer 决定明文/报错)。name 仅用于错误信息。
func pickPEM(inline, file, name string) ([]byte, error) {
	switch {
	case inline != "" && file != "":
		return nil, fmt.Errorf("%s: 内嵌 PEM 与文件路径只能二选一", name)
	case inline != "":
		return []byte(inline), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("%s 读文件: %w", name, err)
		}
		return b, nil
	default:
		return nil, nil
	}
}
