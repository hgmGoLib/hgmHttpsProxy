package hgmHttpsProxyTest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// TestCombos_RoundTripOK 各种「应当连通」的配置组合:都跑一遍真隧道回环,
// 并顺带断言 ClientConfig.Security() 的分级与配置相符。
func TestCombos_RoundTripOK(t *testing.T) {
	cert, key, serverPin := gwCert(t)
	caCert, caKey, caPin := clientCA(t, "ca-good")
	chain, ckey := signClient(t, caCert, caKey, "endpoint-001")
	caPins, err := hgmHttpsProxyClient.ParsePins(caPin)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		server    hgmHttpsProxyServer.ServerConfig // 不含 Listen,newGateway 补
		fwd       func(addr string) string         // 由网关地址拼 forward URL
		withCert  bool                             // 是否注入客户端证书(双向 TLS)
		wantLevel string                           // 期望 Security().Code
	}{
		{
			name:      "https+serverPins+Basic",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}},
			fwd:       func(a string) string { return fmt.Sprintf("https://u:p@%s?serverPins=%s", a, serverPin) },
			wantLevel: "pinned_basic",
		},
		{
			name:      "https+serverPins+clientCaPins+Basic(最安全)",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, ClientCaPins: caPins},
			fwd:       func(a string) string { return fmt.Sprintf("https://u:p@%s?serverPins=%s&clientCaPins=%s", a, serverPin, caPin) },
			withCert:  true,
			wantLevel: "pinned_clientcert_basic",
		},
		{
			name:      "https+serverPins+clientCaPins(无密码)",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, ClientCaPins: caPins},
			fwd:       func(a string) string { return fmt.Sprintf("https://%s?serverPins=%s&clientCaPins=%s", a, serverPin, caPin) },
			withCert:  true,
			wantLevel: "pinned_clientcert",
		},
		{
			name:      "https+无serverPins+Basic(客户端不pin,InsecureSkipVerify)",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}},
			fwd:       func(a string) string { return fmt.Sprintf("https://u:p@%s", a) },
			wantLevel: "no_server_pin",
		},
		{
			name:      "https+serverPins+Basic+nosni",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}},
			fwd:       func(a string) string { return fmt.Sprintf("https://u:p@%s?serverPins=%s&nosni=1", a, serverPin) },
			wantLevel: "pinned_basic",
		},
		{
			name:      "http明文外层+Basic",
			server:    hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"u": "p"}},
			fwd:       func(a string) string { return fmt.Sprintf("http://u:p@%s", a) },
			wantLevel: "plaintext",
		},
		{
			name:      "https+serverPins+Basic+CIDR放行+目标白名单",
			server:    hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, AllowedCIDRs: []string{"127.0.0.0/8"}},
			fwd:       func(a string) string { return fmt.Sprintf("https://u:p@%s?serverPins=%s", a, serverPin) },
			wantLevel: "pinned_basic",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			echo := newEcho(t)
			sc := tc.server
			// 目标白名单按需补当前 echo 地址(只在最后一条用,其余留空=不限)。
			if strings.Contains(tc.name, "目标白名单") {
				sc.TargetAllowlist = []string{echo}
			}
			gw := newGateway(t, sc)

			cfg, err := hgmHttpsProxyClient.ParseForwardURL(tc.fwd(gw.Addr()))
			if err != nil {
				t.Fatalf("ParseForwardURL: %v", err)
			}
			if tc.withCert {
				cfg.ClientCertPEM, cfg.ClientKeyPEM = chain, ckey
			}
			if got := cfg.Security().Code; got != tc.wantLevel {
				t.Fatalf("安全分级: 期望 %q 得 %q", tc.wantLevel, got)
			}
			roundTrip(t, cfg, echo, "nonce-"+tc.name)
		})
	}
}

// TestCombos_Rejected 各种「应当被拒」的组合:断言失败原因(状态码或握手失败),
// 一律 fail-closed,绝不放行。
func TestCombos_Rejected(t *testing.T) {
	cert, key, serverPin := gwCert(t)
	_, _, otherPin := clientCA(t, "ca-other") // 借 CA pin 当「另一张证书的 pin」,与网关证书不符
	_, _, caGoodPin := clientCA(t, "ca-good") // 网关只认这个 CA(只需其 pin)
	caEvilCert, caEvilKey, _ := clientCA(t, "ca-evil")
	goodPins, _ := hgmHttpsProxyClient.ParsePins(caGoodPin)

	t.Run("错误密码→403", func(t *testing.T) {
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:WRONG@%s?serverPins=%s", gw.Addr(), serverPin))
		dialErr(t, cfg, "127.0.0.1:9", "403")
	})

	t.Run("缺认证→407", func(t *testing.T) {
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://%s?serverPins=%s", gw.Addr(), serverPin))
		dialErr(t, cfg, "127.0.0.1:9", "407")
	})

	t.Run("serverPins不符→握手失败", func(t *testing.T) {
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), otherPin))
		dialErr(t, cfg, "127.0.0.1:9", "握手")
	})

	t.Run("目标不在白名单→403", func(t *testing.T) {
		echo := newEcho(t)
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, TargetAllowlist: []string{"api.example.com:443"}})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), serverPin))
		dialErr(t, cfg, echo, "403")
	})

	t.Run("来源CIDR不允许→403", func(t *testing.T) {
		// 只放行 10.0.0.0/8,本地 127.0.0.1 来源应被拒。
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, AllowedCIDRs: []string{"10.0.0.0/8"}})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s", gw.Addr(), serverPin))
		dialErr(t, cfg, "127.0.0.1:9", "403")
	})

	t.Run("clientCaPins:客户端持错CA证书→拒", func(t *testing.T) {
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, ClientCaPins: goodPins})
		evilChain, evilKey := signClient(t, caEvilCert, caEvilKey, "endpoint-001")
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s&clientCaPins=%s", gw.Addr(), serverPin, caGoodPin))
		cfg.ClientCertPEM, cfg.ClientKeyPEM = evilChain, evilKey
		// TLS1.3 下握手 Handshake() 可能在服务端校验客户端证书前即返回,fail-closed 以
		// "tls: ... certificate" 形式在随后读 CONNECT 响应时浮现,故只断言含 "certificate"。
		dialErr(t, cfg, "127.0.0.1:9", "certificate")
	})

	t.Run("clientCaPins:客户端不出证书→拒", func(t *testing.T) {
		gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"u": "p"}, ClientCaPins: goodPins})
		cfg, _ := hgmHttpsProxyClient.ParseForwardURL(fmt.Sprintf("https://u:p@%s?serverPins=%s&clientCaPins=%s", gw.Addr(), serverPin, caGoodPin))
		// 不注入 ClientCertPEM:服务端 RequireAnyClientCert,握手必败。
		dialErr(t, cfg, "127.0.0.1:9", "certificate")
	})
}

// dialErr 断言 cfg.Dial 失败且错误信息含 want 子串。
func dialErr(t *testing.T, cfg *hgmHttpsProxyClient.ClientConfig, target, want string) {
	t.Helper()
	conn, err := cfg.Dial(target, nil)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("期望失败(含 %q),却连上了", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("期望错误含 %q, 得: %v", want, err)
	}
}
