package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
)

// cmdProbe 用代理(forward_to URL)访问一个目标 URL,把目标返回的原始 http/https 响应
// 字节「原样」输出到 stdout(不解析 HTTP)。用来快速验证一条代理 URL 是否可用。
//
// 参数:
//   - -forward=  代理 forward_to URL(同 ParseForwardURL,含 serverPins/clientCaPins 等)
//   - -url=      目标 URL(http:// 或 https://)
//   - -clientCert= -clientKey=  可选:双向 TLS(客户端也出证书)的证书/私钥 PEM 文件路径,
//     当网关配了 clientCaPins 要求客户端出示证书时填。
func cmdProbe(args []string) error {
	forward := argStr(args, "forward", "")
	target := argStr(args, "url", "")
	if forward == "" || target == "" {
		return errors.New("probe 需要 -forward=<代理URL> 和 -url=<目标URL>")
	}
	cfg, err := hgmHttpsProxyClient.ParseForwardURL(forward)
	if err != nil {
		return err
	}
	if cert := argStr(args, "clientCert", ""); cert != "" {
		if cfg.ClientCertPEM, err = os.ReadFile(cert); err != nil {
			return fmt.Errorf("读 clientCert: %w", err)
		}
		key := argStr(args, "clientKey", "")
		if cfg.ClientKeyPEM, err = os.ReadFile(key); err != nil {
			return fmt.Errorf("读 clientKey: %w", err)
		}
	}
	return hgmHttpsProxyClient.Probe(cfg, target, os.Stdout)
}
