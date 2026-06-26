package hgmHttpsProxyClient

// SecurityLevel 一份配置的安全等级,供 UI「配置安全告知」展示。
type SecurityLevel struct {
	Level string // insecure / low / medium / high
	Code  string // 机器可读标识
	Note  string // 人读说明
}

// ClassifySecurity 按设计文档的六档「顺序匹配,首条命中即报」。
// 顺序经过校正:最具体的高/中档在前,泛档在后,避免前一条吞掉后面。
//
// 威胁模型说明(刻意不同于「网上」默认排序):在本机可信、端点主动外连已知网关的
// 场景里,「无客户端认证 → 被公网扫描借道」的发生概率远高于「需占据链路位置的主动
// 中间人」,故无认证排在无 serverPins 之前(更危险)。
func ClassifySecurity(scheme string, hasServerPins, hasClientCaPins, hasBasic bool) SecurityLevel {
	switch {
	case scheme != "https":
		return SecurityLevel{"insecure", "plaintext",
			"明文 http 外层,流量可被被动监听截获"}
	case !hasBasic && !hasClientCaPins:
		return SecurityLevel{"insecure", "open_relay",
			"无任何客户端认证,极可能被公网扫描到直接借道(即使有 serverPins)"}
	case !hasServerPins:
		return SecurityLevel{"low", "no_server_pin",
			"未 pin 服务端证书,可能被中间人攻击截包"}
	case hasClientCaPins && hasBasic:
		return SecurityLevel{"high", "pinned_clientcert_basic",
			"服务端 pin + 客户端证书 + 账号密码,双因子"}
	case hasClientCaPins:
		return SecurityLevel{"medium", "pinned_clientcert",
			"服务端 pin + 客户端证书,问题:每实例需各自证书,较难多实例"}
	default:
		return SecurityLevel{"medium", "pinned_basic",
			"服务端 pin + 账号密码,问题:偷走此 url 即可连接"}
	}
}
