hgmHttpsProxy —— 出口正向代理(CONNECT 隧道,标准 Basic 认证,可选 SPKI pin)
================================================================================

定位
----
端点静态配一次,把命中的流量经一个「标准 HTTPS 正向代理」转发出口。下一跳可以是本
库的网关,也可以是任意支持 http Basic 认证的现成正向代理。无第三方依赖(仅 Go 标准库,
且刻意不依赖 net/http —— 内层 HTTP 解析是手写的极简版)。

协议
----
* 外层:TLS(https,默认自签)或明文(http)。要求 TLS1.3 起步。
* 内层:仅 HTTP CONNECT。即使被代理流量本身是 http GET,也一律走 CONNECT(简化)。
* 鉴权:浏览器标准 Proxy-Authorization: Basic base64(user:pass)(RFC 7617)。
* 缺认证 → 407 Proxy-Authenticate: Basic;认证/目标/来源被拒 → 403;建立 → 200。

包结构(共享代码按项目约定写在客户端包,服务端 import 复用,不另开 proto 包)
----------------------------------------------------------------------
* hgmHttpsProxyClient    —— 客户端 + 共享代码(协议读写 / Basic / SPKI pin / 安全分级 / 证书生成)。纯 API,无命令行解析。
* hgmHttpsProxyServer    —— 网关服务端(校验 + 隧道转发),import 上面的共享代码。纯 API,无命令行解析。
* hgmHttpsProxyCmd —— 网关二进制入口:子命令派发器 + 全部 CLI 实现(serve/gencert/probe/cmdargs)。

  重要:绝大多数调用方(含本项目)是从代码对接的——直接用 ClientConfig.DialContext /
  hgmHttpsProxyServer.NewServer 这些 API。cmd 只是一个示例入口,所有命令行解析都关在 cmd 包里,
  client/server 两个库刻意不含任何 CLI 代码。
* hgmHttpsProxyTest      —— 集成测试包(真 TCP 监听):各配置组合的正确性 + 与 net/http 的协议兼容性
* example/safest         —— 最安全用法的介绍 + 可跑 demo + 自动测试

客户端配置 = 一个 forward_to URL
--------------------------------
最安全(推荐,完整示例见 example/safest):serverPins + clientCaPins + 账号密码,再注入客户端证书。
  https://user:pass@gw.example.com:9443?serverPins=sha256:AAA,sha256:BBB&clientCaPins=sha256:CCC
  cfg.ClientCertPEM, cfg.ClientKeyPEM = ...   // 客户端证书 PEM(第二因子),由集成方注入
这是安全分级 high(pinned_clientcert_basic):服务端被 pin(防假网关/中间人)+ 账号密码(第一
因子)+ 客户端证书(第二因子,偷走 URL 也连不上,还得有客户端私钥)。

query 参数:
* serverPins   服务端叶子证书的 SPKI pin(逗号分隔,命中任一即信任;空=不校验服务端证书)。
* clientCaPins 客户端「上一级 CA」的 SPKI pin(只支持 2 级)——由服务端消费,要求客户端也出示
               证书(双向 TLS)。仍是 https,只是除服务端出证书外、客户端也出一张证书,让服务端
               反过来认证客户端;外层始终 TLS1.3 https。客户端证书 PEM 由集成方注入
               ClientCertPEM/ClientKeyPEM(如复用 enrollment 证书)。
* nosni=1      不发送 SNI(避免明文域名被在线过滤;仅在 TLS1.3 下才真正藏住域名)。

其它(安全性较低,按需取舍):
  https://user:pass@gw:9443?serverPins=sha256:AAA,sha256:BBB&nosni=1   中等:无客户端证书,偷走 url 即可连
  http://user:pass@10.0.0.1:8080                                       不安全:明文外层,可被被动监听

不配 serverPins = 客户端不关注服务端证书(可自签可公网,只要符合 TLS1.3)。
不支持证书有效期 / 吊销列表等(刻意从简,易测正确性)。

SPKI pin 格式
-------------
pin = "sha256:" + base64url(无填充)( SHA-256( DER 编码的 SubjectPublicKeyInfo ) )。
即 RFC 7469(HPKP)沿用、各客户端 pinning 的事实标准。pin 公钥而非整证书:证书续期只要
密钥不变,pin 仍命中。多个 pin 取 OR,务必保留新旧 pin 重叠窗口做轮换,否则丢钥匙会把端点弄成砖。
计算:hgmHttpsProxyClient.ComputeSPKIPin(cert)。

校验语义(重要:外层 TLS 刻意不做标准校验,只认公钥 pin)
--------------------------------------------------------
外层 TLS 一律 InsecureSkipVerify —— 跳过 Go 的标准证书校验,改为「只按 SPKI pin 认公钥」。
两个方向都如此,且都 fail-closed(不匹配立即断开)。这是有意设计,不是偷懒。

A. 客户端认网关(serverPins)。实际只做两条:
   1. 服务端叶子证书(握手里的 rawCerts[0])的 SPKI 命中 serverPins 之一。
   2. (TLS 协议内建,绕不过)对端必须证明持有该叶子公钥对应的私钥,握手才成立。
   合起来 = 你连上的一定是「持有被 pin 的那把私钥」的一方。
   刻意不做、全部跳过:
   * 不验 CA 链 / 信任根(InsecureSkipVerify)。
   * 不验 host / IP:证书 SAN 完全不参与;ServerName 只作为 SNI 发出去,不做主机名匹配;
     nosni=1 时连 SNI 都不发。
   * 不验有效期(NotBefore/NotAfter)、不验 KeyUsage/EKU、不验吊销(CRL/OCSP)。
   推论:网关证书的 SAN 写什么都行(本库不看),可自签、可过期、host 可对不上 —— 只看公钥。

B. 服务端认客户端(clientCaPins,即「客户端也出证书」的双向 TLS)。实际只做:
   1. 客户端须出示「叶子 + 上一级 CA」两张证书(rawCerts 至少 2 个)。
   2. 上一级 CA(rawCerts[1])的 SPKI 命中 clientCaPins。
   3. 叶子确由该 CA 签发:leaf.CheckSignatureFrom(ca) —— 验签名,且要求该 CA 是真 CA
      (BasicConstraints CA:TRUE 且 KeyUsage 含 certSign)。
   4. (TLS 协议内建)客户端须证明持有叶子私钥(CertificateVerify)。
   刻意不做:不验信任根、不验叶子/CA 有效期、不验客户端 EKU、不验吊销。
   好处:只 pin 一个 CA,即可给该 CA 下任意端点签发证书而不必逐个改服务端配置;偷走
        forward_to URL 仍连不上,因为缺叶子私钥。

为什么够安全:pin 的是公钥,TLS 又强制对端证明拥有对应私钥;在「本机可信、主动外连已知网关」
威胁模型下,攻击面收敛到「那把私钥」,比依赖公网 CA 体系更小、更可控。
(注:这只针对外层代理 TLS。probe 子命令访问的最终 https 目标走的是标准证书校验,与此无关。)

安全分级(配置安全告知,按顺序匹配,首条命中即报)
------------------------------------------------
威胁模型:本机可信、端点主动外连已知网关。此场景下「无认证被公网扫描借道」的概率远高于
「需占据链路的主动中间人」,故无认证排在无 serverPins 之前(更危险)。
  1. http                                  → insecure  明文,可被被动监听
  2. 无任何客户端认证(即使有 serverPins)  → insecure  极可能被公网扫描到直接借道
  3. https 无 serverPins                    → low       可能被中间人截包
  4. serverPins + clientCaPins + 账号密码   → high      双因子
  5. serverPins + clientCaPins(无密码)     → medium    每实例需各自证书,较难多实例
  6. serverPins + 账号密码(无 clientCaPins)→ medium    偷走此 url 即可连接
  函数:hgmHttpsProxyClient.ClassifySecurity(...) / ClientConfig.Security()。

用法(客户端,最安全配置)
-------------------------
  cfg, _ := hgmHttpsProxyClient.ParseForwardURL("https://u:p@gw:9443?serverPins=sha256:...&clientCaPins=sha256:...")
  cfg.ClientCertPEM, cfg.ClientKeyPEM = clientCert, clientKey // 客户端证书(第二因子),由集成方注入
  conn, err := cfg.DialContext(ctx, "api.openai.com:443", map[string]string{"X-Endpoint-Id": id})
  // conn 即到目标的隧道,在其上跑端到端 TLS / 任意字节流
  // DialContext:拨号/TLS握手/CONNECT 都跟随 ctx 取消与截止时间(接 http.Transport.DialContext 的推荐入口);
  // Dial(无 ctx)= DialContext(context.Background(), ...) 的薄封装。

用法(服务端)
-------------
  s, _ := hgmHttpsProxyServer.NewServer(hgmHttpsProxyServer.ServerConfig{
      Listen: ":9443", TLSCertPEM: cert, TLSKeyPEM: key,
      AcceptedBasic: map[string]string{"alice": "s3cret"},
      TargetAllowlist: []string{"api.openai.com:443"},
      OnAudit: func(ev hgmHttpsProxyServer.AuditEvent) { /* 注入审计,lib 不依赖具体实现 */ },
      // 可选注入点:
      // DialUpstream: func(ctx, target)(net.Conn,error){...}  // 自定义「下一跳」拨号:区域选路/链式上游代理/自定义解析;nil=默认直连
      // RelayIdleTimeout: 2*time.Minute                       // 隧道空闲超时:两向都连续这么久无字节即断;0=默认2分钟,负=永不超时
      // FailureReasonHeader: "X-ASCP-Failure-Reason"          // 拒绝/失败响应里写失败原因的头名;空=默认 "X-Hp-Failure-Reason"
  })
  s.Listen()            // 可选:提前绑定端口,让 Addr() 在 Serve 前可用、端口占用等错误启动阶段同步暴露(Serve 也会自动调用,幂等)
  go s.Serve()
  ...
  s.Close()             // 立即停:关 listener,不等也不强断在飞隧道
  s.Shutdown(30*time.Second)  // 优雅停(滚动发布):停 accept + 等在飞隧道排空,到点强关剩余并返回错误

  审计:每条隧道产生两条 200 事件——建立时(Reason="")与结束时(Reason="closed",带
  BytesToTarget/BytesToClient/Duration,供计量与对账)。失败走对应 4xx/5xx + Reason。

命令行子命令(hgmHttpsProxyCmd,hgmConsole 风格,参数 -Name=value)
--------------------------------------------------------------------
本库零依赖,故不 import hgmConsole,自带十几行小派发器;子命令实现与参数解析全在 cmd 包内
(serve.go / gencert.go / probe.go / cmdargs.go),client/server 库不含 CLI 代码。
  genServerCert  生成网关自签证书(私钥+证书),打印客户端 serverPins。
                 -cn= -dns=a,b -ip=10.0.0.9(默认 127.0.0.1) -days= -out=前缀
  genClientCA    生成客户端证书(双向 TLS)用的 CA(私钥+自签 CA 证书),打印服务端 ClientCaPins。
                 -cn= -days= -out=前缀
  caSignCert     用 CA 给端点签发客户端证书链(叶子+CA)。
                 -caCert= -caKey= -cn= -days= -out=前缀
  serve          读 JSON 配置启动网关:-Config=server.json。异步 Serve + 监听 Ctrl+C/SIGTERM,
                 收到信号即优雅停服;启动后向 stdout 打印一条「客户端可直接用」的 forward_to URL
                 (Server.ForwardURL 据当前配置实时生成:scheme://user:pass@DisplayIP:实际端口?
                 serverPins=…&clientCaPins=…)。账号密码取 AcceptedBasic 排序最小的一条;serverPins
                 实时算服务端证书 SPKI;无 Basic/无 TLS/无 ClientCaPins 则对应部分不出现。
                 JSON 配置类型 = hgmHttpsProxyServer.ServerFileConfig(放在 server 库并导出,方便上层
                 代码远程下发这份 JSON);ServerFileConfig.ToServerConfig() 完成证书解析与生成。
                 证书聚在 ServerTlsCert 指针字段下(每字段只表示一件事,不重载):
                   内嵌组:TLSCertPEM / TLSKeyPEM(PEM 文本)
                   文件组:TLSCertFile / TLSKeyFile(文件路径;两文件都不存在则首启自动生成并落盘)
                 证书与私钥各自在「内嵌」「文件」里二选一;ServerTlsCert 整体为 nil/空 = 内存生成自签证书。
                 UseHttp=true 则明文 http 监听(忽略 ServerTlsCert,不做 TLS;仅 demo/内网)。
                 其余 JSON 字段:Listen / AcceptedBasic{user:pass} / ClientCaPins[] /
                 AllowedCIDRs[] / TargetAllowlist[] / RelayIdleTimeoutSeconds(0=默认2分钟,负=永不超时) /
                 DisplayIP(打印 URL 用的 IP,空=127.0.0.1,由调用者自行替换成真实可达地址)。
                 (OnAudit/DialUpstream 等函数型注入点只能代码对接,不进 JSON。)
  probe          用代理访问一个目标 URL,把目标返回的原始 http/https 字节原样打到 stdout
                 (不解析 HTTP),用来测一条代理 URL 是否可用。
                 -forward=<代理URL> -url=<目标URL> [-clientCert= -clientKey=]
对应纯 API:hgmHttpsProxyServer.GenServerCert / hgmHttpsProxyClient.GenClientCA / SignClientCert / Probe
(CLI 薄壳在 cmd 包,调这些 API)。

最安全用法
----------
见 example/safest/(readme.txt + 可跑 demo + 自动测试):https + serverPins + clientCaPins(客户端证书/
双向 TLS)+ Basic 叠满 = 分级 high(pinned_clientcert_basic)。go run ./example/safest;go test ./example/safest。

集成约束
--------
* 本库零业务依赖,审计 / 通知 / 策略一律通过 OnAudit 回调或配置注入,不 import 上层项目。
* 双向 TLS 的客户端证书由集成方提供 PEM(本库不感知 enrollment / 任何 PKI 来源)。

限制与部署加固
--------------
* 不支持 TCP 半关闭:隧道任一方向 EOF 即整体断开(relay 全关双向),不会把 client 的
  shutdown(WR) 传播给上游再等其响应。面向 TLS / 双向流式隧道(主用例);依赖 TCP 半关闭
  的明文协议(发完请求即 shutdown 写端、再等响应)可能被截断,不适合用本库代理。
* SSRF / 出口范围:TargetAllowlist 空 = 不限目标。此时已认证端点可经网关 CONNECT 到网关
  所在内网、云 metadata(169.254.169.254)、任意端口 —— 端点在威胁模型里只是半可信,部署到
  云上这是真实横向移动面。生产务必配 TargetAllowlist 收口到明确目标(或用 DialUpstream 在
  下一跳拦截内网段 / 受限端口),否则等于给端点开了一个借网关访问其内网的通道。

测试
----
  cd hgmHttpsProxy && go test ./...
  (e2e 测试自签证书 + 回环目标,不联网。)
* hgmHttpsProxyServer  —— 服务端包内的若干 e2e(pin/Basic/目标白名单/握手 fail-closed)。
* hgmHttpsProxyTest    —— 集成测试包,真 TCP 监听 127.0.0.1:0:
  - combos_test.go   客户端/服务端各配置组合(scheme/serverPins/Basic/clientCaPins/
                     AllowedCIDRs/TargetAllowlist/nosni)的应通回环 + 应拒失败码/握手失败。
  - reject_test.go   安全拒绝矩阵,且断言服务端审计 Reason(客户端只看到笼统的 403/
                     certificate,靠 Reason 区分卡在哪一步):授权/策略(未知用户·错密码·
                     缺认证·CIDR·目标白名单)、双向 TLS 客户端证书各种坏形态(不出证书·只
                     发叶子缺 CA·另一 CA 签·CA 对但叶子伪造)、TLS1.2 客户端被 min1.3 拒、
                     畸形 Proxy-Authorization、NewServer 配置校验。
  - features_test.go DialContext 取消即返回;隧道空闲超时(到点关·有流量不误杀);
                     DialUpstream 下一跳改投。
  - drain_test.go    Shutdown 排空在飞隧道 / 超时强关;Close 立即返回;结束审计的
                     字节数与时长。
  - nethttp_test.go  与 net/http 的协议兼容性三方向:net/http 当代理客户端→本库服务端;
                     本库客户端→net/http 实现的 CONNECT 代理;net/http 流量经本库隧道。
                     (本库运行时不依赖 net/http,仅测试包 import 它做互通反证。)
