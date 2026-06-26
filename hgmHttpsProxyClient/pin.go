package hgmHttpsProxyClient

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Pin 一个公钥指纹:证书 SubjectPublicKeyInfo(SPKI)的 SHA-256。
//
// 这是 RFC 7469(HPKP)沿用、被各客户端 pinning(Android NSC / OkHttp / TrustKit)
// 采用的事实标准格式。pin 公钥而非整证书:证书续期只要密钥不变,SPKI 不变 → pin 仍命中,
// 不会把端点弄成砖。算法标识(RSA/ECDSA/Ed25519)本身就编码在 SPKI 里,无需另指定。
type Pin struct {
	Algo string // 目前仅 "sha256"
	Sum  []byte // 原始哈希字节(sha256 为 32 字节)
}

// ComputeSPKIPin 计算证书 SPKI 的 pin 字符串:"sha256:base64url(无填充)"。
// base64url 是为了能直接放进 URL query(标准 base64 的 +/= 会破坏 query)。
func ComputeSPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// SPKIPinFromCertPEM 从证书 PEM(取第一块)算 SPKI pin 字符串,便于生成证书后直接打印。
func SPKIPinFromCertPEM(certPEM []byte) (string, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return "", errors.New("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	return ComputeSPKIPin(cert), nil
}

// ParsePins 解析逗号分隔的 pin 列表(每项 "sha256:base64")。空串返回 nil。
// 同时兼容 base64url(无填充)与标准 base64,容错运维手抄。
func ParsePins(csv string) ([]Pin, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var pins []Pin
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		algo, b64, ok := strings.Cut(tok, ":")
		if !ok {
			return nil, fmt.Errorf("非法 pin %q,应形如 sha256:base64url", tok)
		}
		if algo != "sha256" {
			return nil, fmt.Errorf("不支持的 pin 算法 %q,仅 sha256", algo)
		}
		sum, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			if sum, err = base64.StdEncoding.DecodeString(b64); err != nil {
				return nil, fmt.Errorf("pin %q base64 解码失败: %w", tok, err)
			}
		}
		if len(sum) != sha256.Size {
			return nil, fmt.Errorf("pin %q 哈希长度非 %d 字节", tok, sha256.Size)
		}
		pins = append(pins, Pin{Algo: algo, Sum: sum})
	}
	return pins, nil
}

// MatchSPKIPin 证书 SPKI 是否命中 pins 中任意一项(OR 语义,支持轮换 overlap)。
// pin/证书均为公开数据,无需常量时间比对。
func MatchSPKIPin(pins []Pin, cert *x509.Certificate) bool {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	for _, p := range pins {
		if p.Algo == "sha256" && bytes.Equal(p.Sum, sum[:]) {
			return true
		}
	}
	return false
}
