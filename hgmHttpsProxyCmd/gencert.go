package main

import (
	"fmt"
	"os"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// 证书相关子命令。底层 crypto 都在 hgmHttpsProxyClient/hgmHttpsProxyServer 的 certgen.go
// (纯 API);这里只是「读参数 → 调库 → 写文件 → 打印 pin」的 CLI 薄壳。

// cmdGenServerCert 生成网关自签证书,打印客户端 serverPins。
// 参数:-cn= -dns=逗号分隔 -ip=逗号分隔(默认 127.0.0.1) -days= -out=前缀。
func cmdGenServerCert(args []string) error {
	cn := argStr(args, "cn", "hgmHttpsProxy-gateway")
	dns := splitCSV(argStr(args, "dns", ""))
	ips := splitCSV(argStr(args, "ip", "127.0.0.1"))
	days := argInt(args, "days", 825)
	out := argStr(args, "out", "gw")

	certPEM, keyPEM, err := hgmHttpsProxyServer.GenServerCert(cn, dns, ips, days)
	if err != nil {
		return err
	}
	if err := writeCertKey(out, certPEM, keyPEM); err != nil {
		return err
	}
	pin, err := hgmHttpsProxyClient.SPKIPinFromCertPEM(certPEM)
	if err != nil {
		return err
	}
	fmt.Printf("已生成网关证书: %s.crt %s.key\n", out, out)
	fmt.Printf("客户端 serverPins 填: %s\n", pin)
	return nil
}

// cmdGenClientCA 生成客户端双向 TLS 用的 CA(私钥 + 自签 CA 证书),打印其 SPKI pin。
// 参数:-cn=CN -days=有效天数 -out=输出前缀。打印出的 pin 填到服务端配置 ClientCaPins。
func cmdGenClientCA(args []string) error {
	cn := argStr(args, "cn", "hgmHttpsProxy-client-ca")
	days := argInt(args, "days", 3650)
	out := argStr(args, "out", "clientca")

	caCertPEM, caKeyPEM, err := hgmHttpsProxyClient.GenClientCA(cn, days)
	if err != nil {
		return err
	}
	if err := writeCertKey(out, caCertPEM, caKeyPEM); err != nil {
		return err
	}
	pin, err := hgmHttpsProxyClient.SPKIPinFromCertPEM(caCertPEM)
	if err != nil {
		return err
	}
	fmt.Printf("已生成客户端 CA: %s.crt %s.key\n", out, out)
	fmt.Printf("服务端 ClientCaPins 填: %s\n", pin)
	return nil
}

// cmdCASignCert 用已有 CA 给端点签发客户端证书链。
// 参数:-caCert= -caKey=(默认 clientca.crt/.key) -cn= -days= -out=。
// 产出 <out>.crt(叶子+CA 链)/ <out>.key,交给端点做双向 TLS。
func cmdCASignCert(args []string) error {
	caCert := argStr(args, "caCert", "clientca.crt")
	caKey := argStr(args, "caKey", "clientca.key")
	cn := argStr(args, "cn", "endpoint")
	days := argInt(args, "days", 825)
	out := argStr(args, "out", "client")

	caCertPEM, err := os.ReadFile(caCert)
	if err != nil {
		return fmt.Errorf("读 caCert %s: %w", caCert, err)
	}
	caKeyPEM, err := os.ReadFile(caKey)
	if err != nil {
		return fmt.Errorf("读 caKey %s: %w", caKey, err)
	}
	chainPEM, keyPEM, err := hgmHttpsProxyClient.SignClientCert(caCertPEM, caKeyPEM, cn, days)
	if err != nil {
		return err
	}
	if err := writeCertKey(out, chainPEM, keyPEM); err != nil {
		return err
	}
	fmt.Printf("已签发客户端证书链: %s.crt(叶子+CA) %s.key\n", out, out)
	return nil
}

// writeCertKey 写 <prefix>.crt(0644)与 <prefix>.key(0600,私钥只给本人)。
func writeCertKey(prefix string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(prefix+".crt", certPEM, 0o644); err != nil {
		return fmt.Errorf("写 %s.crt: %w", prefix, err)
	}
	if err := os.WriteFile(prefix+".key", keyPEM, 0o600); err != nil {
		return fmt.Errorf("写 %s.key: %w", prefix, err)
	}
	return nil
}
