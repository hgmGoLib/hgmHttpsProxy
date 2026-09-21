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

// String 还原成 "sha256:base64url(无填充)"(ComputeSPKIPin/ParsePins 的逆),便于把已解析的
// pin 回填进 forward_to URL 的 serverPins/clientCaPins。
func (p Pin) String() string {
	return p.Algo + ":" + base64.RawURLEncoding.EncodeToString(p.Sum)
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
// 同时兼容 base64url 与标准 base64,有无 = 填充都收,容错运维手抄。
//
// 🔴 解码一律走 Strict():base64 的最后一个字符只有高几位有效(43 字符的 base64url 里
// 末位只用 4 位),非 Strict 的解码器【不检查那几位多余的比特是不是 0】,于是 "…V0c"
// 和 "…V0f" 会解出同一串 32 字节 —— 手抄错最后一个字母照样过闸,再 Pin.String() 回填时
// 又被静默归一成规范形。真实现场是这样的:安装命令收下一个末位写错的
// -clientCaPins,写盘用原串、打印给人粘进控制台的 forward_to 里却是归一后的另一个字符,
// 同一次安装里两处对不上;更要命的是它是【笔误】—— 真正想抄的那个 pin(末位 g)与它
// 解出来的 32 字节根本不是同一个,双向 TLS 必然握手失败,而命令行刚报过"自检通过"。
// 严格解码把这类笔误挡在纯取值校验那一步(调用方据此退 2 · 服务都还没停),
// 兑现「一次 pin 笔误不会断一次隧道」这条运维承诺。
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
		// 字母表(base64url / 标准)× 有无 = 填充 四种写法都收(BUG-004273/004274):
		// 32 字节的规范 base64 本来就是 44 字符带一个 `=`,运维照「32 字节的 base64」手抄出
		// `…uFU=` 这种 base64url 带填充的写法是正常的;此前只收「url 无填充」与「标准带填充」
		// 两种,控制台徽章(同口径补齐再解)判「高」,这里却拒 —— 同一串两边结论相反。
		// 四种都严格解码,解出来的 32 字节是同一串,放宽的只是写法不是判据。
		sum, errURL := base64.RawURLEncoding.Strict().DecodeString(b64)
		if errURL != nil && strings.HasSuffix(b64, "=") {
			sum, errURL = base64.URLEncoding.Strict().DecodeString(b64)
		}
		if errURL != nil {
			// 两条路都失败时【两个原文都打出来】:pin 的正规形状是 base64url,
			// 只报标准 base64 那条会指着 `-`/`_` 说"第 17 字节非法",把人往错处引。
			var errStd error
			if strings.HasSuffix(b64, "=") {
				sum, errStd = base64.StdEncoding.Strict().DecodeString(b64)
			} else {
				sum, errStd = base64.RawStdEncoding.Strict().DecodeString(b64)
			}
			if errStd != nil {
				return nil, fmt.Errorf("pin %q base64 解码失败: 按 base64url 解: %v; 按标准 base64 解: %v",
					tok, errURL, errStd)
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
