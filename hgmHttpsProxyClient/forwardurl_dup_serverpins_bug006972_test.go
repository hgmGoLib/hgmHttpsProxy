// BUG-006972:forward_to 里重复写 serverPins 时,每一个取值都要解析(写残即报错),合法 pin 取并集。
package hgmHttpsProxyClient

import "testing"

func TestParseForwardURLDupServerPinsBug006972(t *testing.T) {
	const v = "sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	const w = "sha256:meW99naEFqw4rXQCW_J5qbRonorSP6IHlCQNyxz_V0c"
	for _, bad := range []string{
		"https://gw:9443?serverPins=" + v + "&serverPins=sha256:AAA",
		"https://gw:9443?serverPins=sha256:AAA&serverPins=" + v,
	} {
		if _, err := ParseForwardURL(bad); err == nil {
			t.Errorf("%q 里有写残的 pin,应当解析失败", bad)
		}
	}
	cfg, err := ParseForwardURL("https://gw:9443?serverPins=" + w + "&serverPins=" + v)
	if err != nil {
		t.Fatalf("两个合法 pin 应当解析成功: %v", err)
	}
	if len(cfg.ServerPins) != 2 || cfg.ServerPins[0].String() != w || cfg.ServerPins[1].String() != v {
		t.Fatalf("两个 pin 都应生效 · 收到 %v", cfg.ServerPins)
	}
}
