package hgmHttpsProxyTest

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyClient"
	"github.com/hgmGoLib/hgmHttpsProxy/hgmHttpsProxyServer"
)

// 更细的「安全拒绝」矩阵。客户端看到的错误往往很笼统(都是 403、或都是 "certificate"),
// 所以这里同时断言服务端审计里的具体 Reason,确保拒绝原因真的是我们以为的那个。

// auditSink 线程安全地收集网关审计事件,供断言「服务端因什么原因拒绝」。
type auditSink struct {
	mu  sync.Mutex
	evs []hgmHttpsProxyServer.AuditEvent
}

func (a *auditSink) record(ev hgmHttpsProxyServer.AuditEvent) {
	a.mu.Lock()
	a.evs = append(a.evs, ev)
	a.mu.Unlock()
}

// waitReason 轮询等待出现一条 Reason 含 want 的审计(审计在服务端发生,可能略晚于客户端报错)。
func (a *auditSink) waitReason(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		for _, ev := range a.evs {
			if strings.Contains(ev.Reason, want) {
				a.mu.Unlock()
				return
			}
		}
		a.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	a.mu.Lock()
	var got []string
	for _, ev := range a.evs {
		got = append(got, fmt.Sprintf("status=%d reason=%q", ev.Status, ev.Reason))
	}
	a.mu.Unlock()
	t.Fatalf("未在审计里等到 Reason 含 %q;实得 %v", want, got)
}

// TestReject_AuthAndPolicyReasons 授权/策略类拒绝:客户端拿到 403/407,
// 服务端审计 Reason 精确到 auth_failed / missing_auth / cidr_denied / target_denied。
func TestReject_AuthAndPolicyReasons(t *testing.T) {
	cert, key, serverPin := gwCert(t)

	cases := []struct {
		name       string
		server     hgmHttpsProxyServer.ServerConfig
		user, pass string // forward URL 里的账号密码(空=不带 userinfo)
		target     string // CONNECT 目标
		wantCode   string // 客户端错误里应含的状态码
		wantReason string // 服务端审计 Reason
	}{
		{
			name:       "未知用户名",
			server:     hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"alice": "pw"}},
			user:       "mallory", pass: "pw",
			target: "127.0.0.1:9", wantCode: "403", wantReason: "auth_failed",
		},
		{
			name:       "已知用户错密码",
			server:     hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"alice": "pw"}},
			user:       "alice", pass: "WRONG",
			target: "127.0.0.1:9", wantCode: "403", wantReason: "auth_failed",
		},
		{
			name:       "完全不带认证头",
			server:     hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"alice": "pw"}},
			target:     "127.0.0.1:9", wantCode: "407", wantReason: "missing_auth",
		},
		{
			name:       "来源CIDR不允许",
			server:     hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"alice": "pw"}, AllowedCIDRs: []string{"10.0.0.0/8"}},
			user:       "alice", pass: "pw",
			target: "127.0.0.1:9", wantCode: "403", wantReason: "cidr_denied",
		},
		{
			name:       "目标不在白名单",
			server:     hgmHttpsProxyServer.ServerConfig{AcceptedBasic: map[string]string{"alice": "pw"}, TargetAllowlist: []string{"only.example.com:443"}},
			user:       "alice", pass: "pw",
			target: "127.0.0.1:9", wantCode: "403", wantReason: "target_denied",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &auditSink{}
			sc := tc.server
			sc.TLSCertPEM, sc.TLSKeyPEM = cert, key
			sc.OnAudit = sink.record
			gw := newGateway(t, sc)

			var fwd string
			if tc.user != "" {
				fwd = fmt.Sprintf("https://%s:%s@%s?serverPins=%s", tc.user, tc.pass, gw.Addr(), serverPin)
			} else {
				fwd = fmt.Sprintf("https://%s?serverPins=%s", gw.Addr(), serverPin)
			}
			cfg, err := hgmHttpsProxyClient.ParseForwardURL(fwd)
			if err != nil {
				t.Fatal(err)
			}
			dialErr(t, cfg, tc.target, tc.wantCode)
			sink.waitReason(t, tc.wantReason)
		})
	}
}

// TestReject_ClientCertShapes 双向 TLS(clientCaPins)下各种「客户端证书不对」的形态。
// 客户端侧都笼统报 "certificate",故靠服务端审计 Reason 区分到底卡在哪一步。
func TestReject_ClientCertShapes(t *testing.T) {
	cert, key, serverPin := gwCert(t)
	caGoodCert, caGoodKey, caGoodPin := clientCA(t, "ca-good")
	caEvilCert, caEvilKey, _ := clientCA(t, "ca-evil")
	goodPins, _ := hgmHttpsProxyClient.ParsePins(caGoodPin)

	// 预先备好几种「坏链」。
	goodChain, goodKey := signClient(t, caGoodCert, caGoodKey, "endpoint-001")
	evilChain, evilKey := signClient(t, caEvilCert, caEvilKey, "endpoint-001")
	leafOnly := firstPEMBlock(t, goodChain)                              // 只有叶子、没带 CA
	forgedChain := append(append([]byte{}, firstPEMBlock(t, evilChain)...), caGoodCert...) // evil 叶子 + good CA

	cases := []struct {
		name       string
		chain, key []byte // 注入的客户端证书链/私钥;nil = 不出示证书
		wantReason string // tls_handshake_failed 里应含的内层原因
	}{
		{name: "完全不出示客户端证书", chain: nil, key: nil, wantReason: "tls_handshake_failed"},
		{name: "只发叶子未带上一级CA", chain: leafOnly, key: goodKey, wantReason: "未提供 叶子+CA"},
		{name: "证书由另一个CA签发", chain: evilChain, key: evilKey, wantReason: "clientCaPins 不匹配"},
		{name: "CA对但叶子非该CA签发(伪造链)", chain: forgedChain, key: evilKey, wantReason: "非该 CA 签发"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &auditSink{}
			gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
				TLSCertPEM: cert, TLSKeyPEM: key,
				AcceptedBasic: map[string]string{"u": "p"},
				ClientCaPins:  goodPins,
				OnAudit:       sink.record,
			})
			cfg, err := hgmHttpsProxyClient.ParseForwardURL(
				fmt.Sprintf("https://u:p@%s?serverPins=%s&clientCaPins=%s", gw.Addr(), serverPin, caGoodPin))
			if err != nil {
				t.Fatal(err)
			}
			if tc.chain != nil {
				cfg.ClientCertPEM, cfg.ClientKeyPEM = tc.chain, tc.key
			}
			// 客户端侧错误笼统(certificate / EOF / broken pipe 皆可能),只断言「没连上」。
			dr := cfg.Dial(hgmHttpsProxyClient.DialReq{Target: "127.0.0.1:9"})
			if dr.Err == nil {
				_ = dr.Conn.Close()
				t.Fatal("坏的客户端证书竟然连上了(双向 TLS 失守)")
			}
			sink.waitReason(t, tc.wantReason) // 真正的判定:服务端因何拒绝
		})
	}
}

// TestReject_TLS12ClientByGateway 网关强制 TLS1.3:一个只肯说 TLS1.2 的客户端必须被拒。
func TestReject_TLS12ClientByGateway(t *testing.T) {
	cert, key, _ := gwCert(t)
	sink := &auditSink{}
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
		OnAudit:       sink.record,
	})

	raw, err := net.Dial("tcp", gw.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 测试:只验版本协商被拒
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12, // 故意封顶 1.2
	})
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("TLS1.2 客户端竟握手成功(应被网关的 min TLS1.3 拒)")
	}
	sink.waitReason(t, "tls_handshake_failed")
}

// TestReject_MalformedProxyAuth 认证头本身畸形(非合法 Basic / base64 解不开)→ 403 auth_failed。
// 用底层协议函数手搓一个坏 CONNECT,正常客户端不会发出这种头。
func TestReject_MalformedProxyAuth(t *testing.T) {
	cert, key, _ := gwCert(t)
	sink := &auditSink{}
	gw := newGateway(t, hgmHttpsProxyServer.ServerConfig{
		TLSCertPEM: cert, TLSKeyPEM: key,
		AcceptedBasic: map[string]string{"u": "p"},
		OnAudit:       sink.record,
	})

	raw, err := net.Dial("tcp", gw.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // 测试
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS 握手不应失败: %v", err)
	}
	// "Basic %%%" —— 前缀合法但 base64 解不开,服务端 ParseBasicAuth 失败 → auth_failed。
	if err := hgmHttpsProxyClient.WriteConnectRequest(tc, "127.0.0.1:9", "Basic %%%not-base64%%%"); err != nil {
		t.Fatal(err)
	}
	code, _, _, err := hgmHttpsProxyClient.ReadConnectResponseStatus(bufio.NewReader(tc))
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	if code != 403 {
		t.Fatalf("期望 403,得 %d", code)
	}
	sink.waitReason(t, "auth_failed")
}

// TestReject_ServerConfigValidation NewServer 在装配阶段就拒掉危险/自相矛盾的配置。
func TestReject_ServerConfigValidation(t *testing.T) {
	cert, key, _ := gwCert(t)
	caPins, _ := hgmHttpsProxyClient.ParsePins("sha256:" + strings.Repeat("A", 43))

	cases := []struct {
		name string
		cfg  hgmHttpsProxyServer.ServerConfig
		want string
	}{
		{
			name: "Listen为空",
			cfg:  hgmHttpsProxyServer.ServerConfig{TLSCertPEM: cert, TLSKeyPEM: key},
			want: "Listen",
		},
		{
			name: "只给证书不给私钥",
			cfg:  hgmHttpsProxyServer.ServerConfig{Listen: "127.0.0.1:0", TLSCertPEM: cert},
			want: "必须同时提供",
		},
		{
			name: "clientCaPins却是明文监听(无TLS做不了双向TLS)",
			cfg:  hgmHttpsProxyServer.ServerConfig{Listen: "127.0.0.1:0", ClientCaPins: caPins},
			want: "需要 TLS",
		},
		{
			name: "AcceptedBasic含空用户名",
			cfg:  hgmHttpsProxyServer.ServerConfig{Listen: "127.0.0.1:0", TLSCertPEM: cert, TLSKeyPEM: key, AcceptedBasic: map[string]string{"": "p"}},
			want: "空 user",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hgmHttpsProxyServer.NewServer(tc.cfg)
			if err == nil {
				t.Fatal("危险配置竟通过了 NewServer 校验")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误含 %q, 得: %v", tc.want, err)
			}
		})
	}
}

// firstPEMBlock 取 PEM 字节里的第一块并重新编码(用来从「叶子+CA」链里抠出单独的叶子)。
func firstPEMBlock(t *testing.T, p []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatal("PEM 解析失败")
	}
	return pem.EncodeToMemory(blk)
}
