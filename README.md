# hgmHttpsProxy

出口正向代理:CONNECT 隧道 + 标准 Basic 认证 + 可选 SPKI pin。零第三方依赖(仅 Go 标准库,
内层 HTTP 解析手写,刻意不依赖 `net/http`)。

> 完整文档以 [`readme.txt`](readme.txt) 为准,本文件只是 GitHub 落地页摘要。

## 定位

端点静态配一次,把命中的流量经一个「标准 HTTPS 正向代理」转发出口。下一跳可以是本库的网关,
也可以是任意支持 HTTP Basic 认证的现成正向代理。

## 协议

- 外层:TLS(https,默认自签)或明文(http),要求 **TLS 1.3** 起步。
- 内层:仅 HTTP `CONNECT`(即使被代理流量是 http GET 也一律走 CONNECT)。
- 鉴权:浏览器标准 `Proxy-Authorization: Basic base64(user:pass)`(RFC 7617)。
- 缺认证 → `407`;认证 / 目标 / 来源被拒 → `403`;隧道建立 → `200`。

## 包结构

| 包 | 作用 |
| --- | --- |
| `hgmHttpsProxyClient` | 客户端 + 客户端/服务端共享代码(协议读写 / Basic / SPKI pin / 安全分级 / 证书生成)。纯 API。 |
| `hgmHttpsProxyServer` | 网关服务端(校验 + 隧道转发 + 优雅停服)。纯 API。 |
| `hgmHttpsProxyCmd` | 网关二进制入口 + 全部 CLI 实现(serve / gencert / probe)。 |
| `hgmHttpsProxyTest` | 集成测试包(真 TCP 监听)。 |
| `example/safest` | 最安全用法介绍 + 可跑 demo + 自动测试。 |

绝大多数调用方从代码对接 —— 直接用 `ClientConfig.Dial` / `hgmHttpsProxyServer.NewServer`;
CLI 只是示例入口,两个库刻意不含命令行代码。

## 客户端用法(最安全配置)

```go
cfg, _ := hgmHttpsProxyClient.ParseForwardURL(
    "https://u:p@gw:9443?serverPins=sha256:...&clientCaPins=sha256:...")
cfg.ClientCertPEM, cfg.ClientKeyPEM = clientCert, clientKey // 客户端证书(第二因子)
resp := cfg.Dial(hgmHttpsProxyClient.DialReq{Ctx: ctx, Target: "api.openai.com:443"})
// resp.Conn 即到目标的隧道(成功时),resp.Status = 网关 CONNECT 响应码,resp.Err = 失败原因。
// 单入参 DialReq、单返回 DialResp;DialReq.Ctx 控制取消/超时(nil = Background)。
```

这是安全分级 **high**(`pinned_clientcert_basic`):服务端被 pin(防假网关/中间人)+ 账号密码
(第一因子)+ 客户端证书(第二因子,偷走 URL 也连不上,还得有客户端私钥)。

## 服务端用法

```go
s, _ := hgmHttpsProxyServer.NewServer(hgmHttpsProxyServer.ServerConfig{
    Listen: ":9443", TLSCertPEM: cert, TLSKeyPEM: key,
    AcceptedBasic:   map[string]string{"alice": "s3cret"},
    TargetAllowlist: []string{"api.openai.com:443"},
    OnAudit: func(ev hgmHttpsProxyServer.AuditEvent) { /* 注入审计 */ },
})
s.Serve()
```

## 安全分级

威胁模型:本机可信、端点主动外连已知网关。按顺序匹配,首条命中即报:

| 配置 | 分级 |
| --- | --- |
| 明文 http 外层 | `insecure`(可被被动监听) |
| 无任何客户端认证(即使有 serverPins) | `insecure`(极可能被公网扫描借道) |
| https 无 serverPins | `low`(可能被中间人) |
| serverPins + clientCaPins + 账号密码 | `high`(双因子) |
| serverPins + clientCaPins(无密码) | `medium` |
| serverPins + 账号密码(无 clientCaPins) | `medium` |

## 限制与部署加固

- **不支持 TCP 半关闭**:隧道任一方向 EOF 即整体断开,不传播 `shutdown(WR)`。面向 TLS / 双向
  流式隧道;依赖 TCP 半关闭的明文协议可能被截断,不适合用本库代理。
- **SSRF / 出口范围**:`TargetAllowlist` 空 = 不限目标,已认证端点可经网关 CONNECT 到网关内网、
  云 metadata(`169.254.169.254`)、任意端口。生产务必配 `TargetAllowlist`(或用 `DialUpstream`
  在下一跳拦内网段 / 受限端口)。

## 测试

```sh
cd hgmHttpsProxy && go test ./...   # 自签证书 + 回环目标,不联网
```

## License

[The Unlicense](LICENSE)(公有领域)+ SQLite 式祝福。随便用。
