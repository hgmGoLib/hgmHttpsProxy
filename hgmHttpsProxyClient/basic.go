package hgmHttpsProxyClient

import (
	"encoding/base64"
	"strings"
)

// EncodeBasicAuth 返回 "Basic base64(user:pass)";user、pass 全空返回空串(不发认证)。
func EncodeBasicAuth(user, pass string) string {
	if user == "" && pass == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// ParseBasicAuth 解析 "Basic base64(user:pass)"(前缀大小写不敏感)。
func ParseBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	s := string(raw)
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
