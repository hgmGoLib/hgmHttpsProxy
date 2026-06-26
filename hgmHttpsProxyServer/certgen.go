package hgmHttpsProxyServer

import "github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"

// GenServerCert 生成网关自签 TLS 证书(私钥 + 证书)。dnsNames/ips 必须覆盖端点
// forward_to 里写的网关 host(或客户端配 nosni)。其 SPKI pin 即客户端 serverPins。
// 底层 crypto 复用客户端包的共享实现。
func GenServerCert(commonName string, dnsNames, ips []string, days int) (certPEM, keyPEM []byte, err error) {
	return hgmHttpsProxyClient.GenSelfSignedTLS(commonName, dnsNames, ips, days)
}
