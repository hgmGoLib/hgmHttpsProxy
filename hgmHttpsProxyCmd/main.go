// Command hgmHttpsProxyCmd 出口代理网关二进制入口,带子命令。
//
// 子命令派发是 hgmConsole 风格(os.Args[1]=命令名,参数走 -Name=value);但本库刻意
// 零依赖,故不 import hgmLib/hgmConsole,自带一个十几行的小派发器。
//
// 注意:各子命令的「实现」就在本 cmd 包内(serve.go / gencert.go / probe.go / cmdargs.go)。
// hgmHttpsProxyClient / hgmHttpsProxyServer 两个库刻意只放纯 API、不含任何命令行解析代码——
// 绝大多数调用方(包括本项目)是从代码对接的,cmd 只是其中一个示例入口。
//
// 例:
//
//	hgmHttpsProxyCmd genServerCert -ip=10.0.0.9 -out=gw       # 生成网关证书 + 打印 serverPins
//	hgmHttpsProxyCmd genClientCA -out=clientca                # 生成客户端 CA + 打印 ClientCaPins
//	hgmHttpsProxyCmd caSignCert -caCert=clientca.crt -caKey=clientca.key -cn=endpoint-001 -out=client
//	hgmHttpsProxyCmd serve -Config=server.json                # 读 JSON 配置启动网关
//	hgmHttpsProxyCmd probe -forward=https://u:p@gw:9443?serverPins=sha256:... -url=https://example.com/  # 测代理可用
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var commands = []struct {
	name string
	desc string
	run  func([]string) error
}{
	{"serve", "读 JSON 配置启动网关: -Config=server.json", cmdServe},
	{"genServerCert", "生成网关自签证书并打印 serverPins: -cn= -dns= -ip= -days= -out=", cmdGenServerCert},
	{"genClientCA", "生成客户端证书(双向TLS)的 CA 并打印 ClientCaPins: -cn= -days= -out=", cmdGenClientCA},
	{"caSignCert", "用 CA 签发客户端证书链: -caCert= -caKey= -cn= -days= -out=", cmdCASignCert},
	{"probe", "用代理访问目标 URL 并原样输出响应(测代理可用): -forward= -url= [-clientCert= -clientKey=]", cmdProbe},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	for _, c := range commands {
		if strings.EqualFold(c.name, name) {
			if err := c.run(os.Args[2:]); err != nil {
				log.Fatalf("%s: %v", c.name, err)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", name)
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, "用法: hgmHttpsProxyCmd <子命令> [-Name=value ...]\n\n子命令:\n")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", c.name, c.desc)
	}
}
