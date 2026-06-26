example/safest —— hgmHttpsProxy 最安全用法
==========================================

目标
----
把安全护栏叠满,达到安全分级 high(pinned_clientcert_basic)。威胁模型见上层 readme.txt:
本机可信、端点主动外连已知网关,最该防的是「无认证被公网扫描借道」和「假网关/中间人」。

四道护栏
--------
1. 外层 https + TLS1.3        链路加密,无降级。
2. serverPins                客户端只 pin 网关叶子证书的公钥 SPKI(不验 CA/host/有效期,见上层
                             readme「校验语义」)→ 防主动中间人 / 假网关(自签也安全)。
3. clientCaPins + 双向 TLS   仍是 https,但客户端也出示一张证书,网关 pin 它「上一级 CA」
                             的 SPKI 来反认证客户端(这就是双向 TLS)。第二因子:光偷走
                             forward_to URL(账号密码都在里面)也连不上,还得有客户端私钥。
4. Basic 账号密码            第一因子。
(另:TargetAllowlist 只放行明确目标。)

命令行一条龙(用 hgmHttpsProxyCmd)
-----------------------------------------
  # 1. 网关证书 + 打印 serverPins
  hgmHttpsProxyCmd genServerCert -ip=10.0.0.9 -out=gw
  # 2. 客户端 CA + 打印 clientCaPins
  hgmHttpsProxyCmd genClientCA -out=clientca
  # 3. 用 CA 给端点签发客户端证书链
  hgmHttpsProxyCmd caSignCert -caCert=clientca.crt -caKey=clientca.key -cn=endpoint-001 -out=client
  # 4. 写 server.json(把 genServerCert / genClientCA 打印的值填进去),启动网关
  hgmHttpsProxyCmd serve -Config=server.json
  # 5.(可选)从端点机器测代理是否可用,原样打印目标响应
  hgmHttpsProxyCmd probe -forward='https://endpoint-001:S3cr3t-Pa55@10.0.0.9:9443?serverPins=sha256:<gw pin>&clientCaPins=sha256:<ca pin>' \
                         -url=https://api.openai.com/ -clientCert=client.crt -clientKey=client.key

server.json(证书/私钥两组字段,各自二选一:内嵌 PEM 或文件路径)
------------------------------------------------------------------
  {
    "Listen": ":9443",
    "TLSCertFile": "gw.crt",
    "TLSKeyFile": "gw.key",
    "AcceptedBasic": { "endpoint-001": "S3cr3t-Pa55" },
    "ClientCaPins": [ "sha256:<genClientCA 打印的 pin>" ],
    "AllowedCIDRs": [ "10.0.0.0/8" ],
    "TargetAllowlist": [ "api.openai.com:443" ]
  }
  (内嵌写法:把 TLSCertFile/TLSKeyFile 换成 TLSCertPEM/TLSKeyPEM,值放 PEM 文本。)

端点侧 forward_to
-----------------
  https://endpoint-001:S3cr3t-Pa55@10.0.0.9:9443?serverPins=sha256:<gw pin>&clientCaPins=sha256:<ca pin>
  并注入双向 TLS 证书:cfg.ClientCertPEM/ClientKeyPEM = client.crt/client.key 的内容。

代码演示
--------
main.go 全程内存自签证书 + 回环目标跑通上面整条链(不联网),打印每一步。
  go run ./example/safest

自动测试(验证正确性)
----------------------
  go test ./example/safest
* TestSafestDemo               正向:分级=pinned_clientcert_basic + 隧道回环成功。
* TestSafestRejectsWrongClientCA  反向:偷了 URL 但客户端证书是另一个 CA 签的 → 双向 TLS 拒(第二因子有效)。
