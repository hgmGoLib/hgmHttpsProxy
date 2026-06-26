package main

import (
	"strconv"
	"strings"
)

// 极简命令行参数读取(hgmConsole 风格:只认 -Name=value)。本库刻意零依赖,故不 import
// hgmLib/hgmConsole,自带这几个够用的小工具。只有 CLI 入口用,所以留在 cmd 包里,
// 不污染 hgmHttpsProxyClient / hgmHttpsProxyServer 这两个纯 API 库。

// argStr 读取 -Name=value;找不到返回 def。Name 区分大小写。
func argStr(args []string, name, def string) string {
	prefix := "-" + name + "="
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return a[len(prefix):]
		}
	}
	return def
}

// argInt 读取 -Name=整数;缺失或非法返回 def。
func argInt(args []string, name string, def int) int {
	s := argStr(args, name, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// splitCSV 逗号分隔 + 去空白 + 丢空项。
func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
