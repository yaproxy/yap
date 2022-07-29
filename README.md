# [WIP] Yap - Yet Another Proxy powered by Golang

[![Docker](https://github.com/yaproxy/yap/actions/workflows/docker.yml/badge.svg?branch=master)](https://github.com/yaproxy/yap/actions/workflows/docker.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/yaproxy/yap?style=flat-square)](https://goreportcard.com/report/yaproxy/yap) [![Apache License Version 2.0](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

Yap is a HTTP1.1/HTTP2 proxy which forked and refactored from [branch vps of Goproxy](https://github.com/phuslu/goproxy/tree/server.vps)

## Usage

First of all, download the latest Yap program from [Release](https://github.com/yaproxy/yap/releases) page according to your os and arch.

### Prepare for Server

* A domain: `example.org`
* Certificate for the domain: `example.org.cer`
* Key of the certificate for the domain: `example.org.key`

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

### Use Yap

#### 1. Use HTTP2 Proxy in Chrome or Firefox

Create a new pac proxy configuration for you browser and setting:

```pac
function FindProxyForURL(url, host) {
  return "HTTPS example.org:443";
}
```

#### 2. Use Yap in Proxy Chains

```toml
[http]
listen = "localhost:8088"
upstream_proxy = "https://example.org:443"
```

```shell
./yap yap.toml
```

Config HTTP Proxy `localhost:8088` for you application.

### Enjoy you life

## Configuration

Yap supports multiple format configuration files such as `toml`, `yaml` and so on.

### Section - default

TBD

### Section - http2

`http2` section contains a list for HTTP2 proxy.

* network - optional

  The network must be a stream-oriented network:
  > "tcp", "tcp4", "tcp6", "unix" or "unixpacket".

  Currently, only support `tcp`, `tcp4`, `tcp6`.

* listen

  The syntax of listen is "host:port", e.g. ":443"

* server_name

  The server name for http2 proxy, should be a list, such as `["example.org", "yap.example.org"]`

* proxy_fallback - optional

  The fallback URL for non-proxy request

* pem - optional

  The pem file location for key pair contains cert and key, if pem is setting, the `cert_file` and `key_file` will be not used.

* cert_file - optional

  The certificate file location

* key_file - optional

  The key file location

* upstream_proxy - optional

  The upstream proxy URL, used for proxy chain.

* proxy_auth_method - optional

  The proxy authenticate method, currently contains 3 options: "pam", "htpasswd", "build-in".

  Leave it blank for disable proxy authenticate

* proxy_auth_htpasswd_path - optional

  The htpasswd file location.

  Only used when `proxy_auth_method` is set to `htpasswd`.

* proxy_auth_buildin_credential - optional

  The build-in authentication credential.
  Only used when `proxy_auth_method` is set to `build-in`.

### Section - http

* network - optional

  The network must be a stream-oriented network:
  > "tcp", "tcp4", "tcp6", "unix" or "unixpacket".

  Currently, only support `tcp`, `tcp4`, `tcp6`.

* listen

  The syntax of listen is "host:port", e.g. ":443"

* upstream_proxy - optional

  The upstream proxy URL, used for proxy chain.

* proxy_auth_method - optional

  The proxy authenticate method, currently contains 3 options: "pam", "htpasswd", "build-in".

  Leave it blank for disable proxy authenticate

  Please reference [Authentication section](#authentication).

* proxy_auth_htpasswd_path - optional

  The htpasswd file location.

  Only used when `proxy_auth_method` is set to `htpasswd`.

* proxy_auth_buildin_credential - optional

  The build-in authentication credential.
  Only used when `proxy_auth_method` is set to `build-in`.

## Authentication

Yap supports two auth methods.

### Build-in Authentication

Set `proxy_auth_method` to `build-in`.
Set `proxy_auth_buildin_credential` to `username:password`.

### Basic Authentication - htpasswd file auth

Set `proxy_auth_method` to `htpasswd`.
Set `proxy_auth_htpasswd_path` to htpasswd file path.

Configuration:

```toml
# ...
proxy_auth_method = "htpasswd"
proxy_auth_htpasswd_path = "/path/to/htpasswd"
# ...
```

Generate htpasswd:

```shell
htpasswd -bc /path/to/htpasswd username passwd
```

### PAM Authentication

Install `python` for PAM authentication.
Set `proxy_auth_method` to `pam`.

## Use Yap in Docker

Quick start:

```
docker run -d \
    -v /path/to/yap.toml:/yap.toml \
    -v /path/to/example.cert:/example.cert \
    -v /path/to/example.key:/example.key \
    -v /path/to/htpasswd:/htpasswd \
    -p 443:443 \
    -p 8088:8088 \
    yaproxy/yap
```

You can find more details from [Yap in Docker hub](https://hub.docker.com/r/yaproxy/yap/).

## Contributing

Contributions are welcome.

## Copyright / License

Copyright 2013-2017 Yaproxy

This software is licensed under the terms of the Apache License Version 2. See the [LICENSE](./LICENSE) file.