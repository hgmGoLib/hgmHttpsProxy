package hgmHttpsProxyClient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// 证书/私钥生成。客户端 CA、CA 签发叶子、以及服务端自签证书(被服务端包薄封一层调用)
// 的底层 crypto 都在这里 —— 按项目约定,客户端/服务端共享代码写在客户端包。
//
// 一律 ECDSA P-256 + PKCS#8 私钥 PEM + TLS1.3。刻意不做有效期吊销等复杂 PKI。

// GenSelfSignedTLS 生成自签 TLS 服务端证书(私钥 + 证书)。其 SPKI pin 即 serverPins。
//
// 注意:本库客户端只 pin 公钥、不校验 SAN(见 readme「校验语义」),所以 dnsNames/ips 写什么
// 都不影响连通性。这里仍要求至少给一个 SAN,只是为了生成一张「规整」的证书(也兼容万一有人
// 改用标准 TLS 校验去连它);默认填 127.0.0.1 即可。
func GenSelfSignedTLS(commonName string, dnsNames, ips []string, days int) (certPEM, keyPEM []byte, err error) {
	ipList, err := parseIPs(ips)
	if err != nil {
		return nil, nil, err
	}
	if len(dnsNames) == 0 && len(ipList) == 0 {
		return nil, nil, errors.New("服务端证书至少需要一个 DNS 或 IP SAN")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipList,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = keyToPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return certToPEM(der), keyPEM, nil
}

// GenClientCA 生成客户端双向 TLS 用的 CA(私钥 + 自签 CA 证书)。其 SPKI pin 即服务端 ClientCaPins。
func GenClientCA(commonName string, days int) (caCertPEM, caKeyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // 只签叶子,不再下挂中间 CA
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	caKeyPEM, err = keyToPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return certToPEM(der), caKeyPEM, nil
}

// SignClientCert 用已有 CA 给端点签发客户端叶子证书。
// 返回的 certPEM 是「叶子 + CA」证书链:双向 TLS 握手时客户端需把 CA 一并发给服务端,
// 服务端的 clientCaPins 校验依赖 rawCerts[1] 取到这一级 CA。
func SignClientCert(caCertPEM, caKeyPEM []byte, commonName string, days int) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := parseCertKey(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, errors.New("提供的 CA 证书 IsCA=false,不能签发")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	leafKeyPEM, err := keyToPEM(leafKey)
	if err != nil {
		return nil, nil, err
	}
	// 叶子 PEM 后面拼上 CA PEM,构成可直接给 tls.X509KeyPair 的证书链。
	chain := append(certToPEM(der), caCertPEM...)
	return chain, leafKeyPEM, nil
}

// parseCertKey 解析一份证书 PEM(取第一块)与 ECDSA 私钥 PEM。
func parseCertKey(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("私钥 PEM 解析失败")
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("私钥不是 ECDSA")
	}
	return cert, key, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func keyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func certToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func parseIPs(ips []string) ([]net.IP, error) {
	var out []net.IP
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("非法 IP %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}
