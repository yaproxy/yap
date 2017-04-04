# [WIP] Yap - Yet Another Proxy powered by Golang

[![Linux Build Status](https://img.shields.io/travis/yaproxy/yap.svg?style=flat-square&label=linux+build)](https://travis-ci.org/yaproxy/yap) [![Go Report Card](https://goreportcard.com/badge/github.com/yaproxy/yap?style=flat-square)](https://goreportcard.com/report/yaproxy/yap) [![Apache License Version 2.0](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

Yap is a HTTP1.1/HTTP2 proxy which forked and refactored from [branch vps of Goproxy](https://github.com/phuslu/goproxy/tree/server.vps)

## Usage

First of all, download the latest Yap program from [Release](https://github.com/yaproxy/yap/releases) page according to your os and arch.

### Create a config file `yap.toml`

```toml
[default]
reject_nil_sni = false

[[http2]]
listen = ":443"
# server name for http2 proxy
server_name = ["example.org"]
# cert file
cert_file = "example.org.cer"
# key file
key_file = "example.org.key"

[http]
listen = ":8088"
```

### Start Yap Server

```shell
./yap yap.toml
```

### Use HTTP2 Proxy in Chrome

Add a new pac proxy configuration for you Chrome and setting:

```pac
function FindProxyForURL(url, host) {
  return "HTTPS example.org:443";
}
```

### Enjoy you life
