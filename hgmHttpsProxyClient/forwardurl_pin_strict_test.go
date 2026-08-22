// forwardurl_pin_strict_test.go — 两条「拨号之前就该判掉」的取值校验。
//
// 一:`https://:9443` 的 url.Host 是 ":9443"(非空)但主机名是空的,
//     老写法放行 → 真去拨了本机 127.0.0.1:9443。
// 二:base64 末位只有高 4 位有效,非 Strict 解码不查多余比特 →
//     手抄错最后一个字母的 pin 照样过闸,回填时又被静默归一成另一个字符。
package hgmHttpsProxyClient

import "testing"

func TestParseForwardURLRejectsEmptyHostname(t *testing.T) {
	for _, bad := range []string{"https://:9443", "http://:80", "https://"} {
		if _, err := ParseForwardURL(bad); err == nil {
			t.Errorf("%q 缺主机名,应当解析失败(否则会被当成本机去拨)", bad)
		}
	}
	for _, ok := range []string{"https://a.b:9443", "http://10.0.0.1:8080", "http://[::1]:8080", "https://a.b"} {
		if _, err := ParseForwardURL(ok); err != nil {
			t.Errorf("%q 是合法网关地址,却被拒了: %v", ok, err)
		}
	}
}

func TestParsePinsRejectsNonCanonicalTail(t *testing.T) {
	// 同一串的规范形是 …V0c;末位低位非零的 …V0f 解出来字节一模一样,
	// 于是"写盘用原串、打印用回填串"两处对不上,而它其实是一次笔误。
	const canonical = "sha256:meW99naEFqw4rXQCW_J5qbRonorSP6IHlCQNyxz_V0c"
	const typo = "sha256:meW99naEFqw4rXQCW_J5qbRonorSP6IHlCQNyxz_V0f"

	pins, err := ParsePins(canonical)
	if err != nil {
		t.Fatalf("规范 pin 应当解析成功: %v", err)
	}
	if got := pins[0].String(); got != canonical {
		t.Fatalf("规范 pin 回填后应当一字不差 · 收到 %q", got)
	}
	if _, err := ParsePins(typo); err == nil {
		t.Errorf("%q 不是规范 base64url,应当当场报错(调用方据此退 2,不该停服务)", typo)
	}
}
