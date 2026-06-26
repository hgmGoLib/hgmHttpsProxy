// Package hgmHttpsProxyTest 是 hgmHttpsProxy 的集成测试包(黑盒,真 TCP 监听 127.0.0.1:0)。
//
// 它不属于产品运行路径,只在 `go test` 时编译,故这里可以、且刻意 import net/http ——
// 产品库(client/server)零依赖、不碰 net/http;本包正是要用 net/http 反过来验证:
// 本库手写的 CONNECT 线协议与标准 net/http 双向兼容。
//
// 三组测试:
//   - combos_test.go    客户端/服务端各种配置组合的正确性(scheme / serverPins /
//                       Basic / clientCaPins / AllowedCIDRs / TargetAllowlist / nosni),
//                       既验证应通的回环成功,也验证应拒的失败码/握手失败。
//   - nethttp_test.go   与 net/http 的协议兼容性,三个方向:
//                         A. net/http 当代理客户端 → 本库服务端(本库 CONNECT 被标准客户端理解)
//                         B. 本库客户端 → net/http 实现的 CONNECT 代理(本库 CONNECT 被标准服务端理解)
//                         C. net/http Transport 的流量经本库客户端隧道到 net/http 目标(隧道字节透明)
//   - fixtures_test.go  共享测试夹具(证书/网关/回环目标/隧道回环断言)。
//
// 运行:cd hgmHttpsProxy && GOWORK=off go test ./hgmHttpsProxyTest
package hgmHttpsProxyTest
