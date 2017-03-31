package yap

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/naoina/toml"
	"github.com/phuslu/glog"
	"github.com/yaproxy/yap/yaputil"
	"github.com/phuslu/goproxy/httpproxy/proxy"
	"golang.org/x/net/http2"
)

var (
	version = "r1"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// TCPListener customize net.TCPListener for Yap
type TCPListener struct {
	*net.TCPListener
}

// Accept implements Accept interface
func (ln TCPListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	tc.SetReadBuffer(32 * 1024)
	tc.SetWriteBuffer(32 * 1024)
	return tc, nil
}

// Config contains the configuration for Yap
type Config struct {
	Default struct {
		LogLevel     int
		DaemonStderr string
		RejectNilSni bool
	}
	HTTP2 []struct {
		Network string
		Listen  string

		ServerName []string

		KeyFile  string
		CertFile string
		PEM      string

		ClientAuthFile string
		ClientAuthPem  string

		UpstreamProxy string

		ProxyFallback   string
		DisableProxy    bool
		ProxyAuthMethod string
	}
	HTTP struct {
		Network string
		Listen  string

		UpstreamProxy string

		ProxyAuthMethod string
	}
}

// Main loads config and start Yap
func Main() {
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Print(version)
		return
	}

	// for glog
	yaputil.SetFlagsIfAbsent(map[string]string{
		"logtostderr": "true",
		"v":           "2",
	})
	flag.Parse()

	filename := flag.Arg(0)
	tomlData, err := loadConfigData(filename)

	var config Config
	if err = toml.Unmarshal(tomlData, &config); err != nil {
		glog.Fatalf("toml.Decode(%s) error: %+v\n", tomlData, err)
	}

	dialer := newDialer()

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		},
		TLSHandshakeTimeout: 16 * time.Second,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     180,
		DisableCompression:  false,
	}

	cm := &CertManager{
		RejectNilSni: config.Default.RejectNilSni,
	}

	// http2 server
	http2Handler := &MultiSNHandler{
		Handlers:    map[string]http.Handler{},
		ServerNames: []string{},
	}

	loadHTTP2Handler(http2Handler, config, transport, dialer, cm)

	http2Srv := &http.Server{
		Handler: http2Handler,
		TLSConfig: &tls.Config{
			GetConfigForClient: cm.GetConfigForClient,
		},
	}

	http2.ConfigureServer(http2Srv, &http2.Server{})

	seen := make(map[string]struct{})
	serveHTTP2(config, seen, http2Srv)

	// http server
	if config.HTTP.Listen != "" {
		server := config.HTTP
		network := server.Network
		if network == "" {
			network = "tcp"
		}
		addr := server.Listen
		if _, ok := seen[network+":"+addr]; ok {
			glog.Fatalf("Yap: addr(%#v) already listened by http2", addr)
		}

		ln, err := net.Listen(network, addr)
		if err != nil {
			glog.Fatalf("Listen(%s) error: %s", addr, err)
		}

		handler := &HTTPHandler{
			Transport: transport,
		}

		if server.UpstreamProxy != "" {
			handler.Transport = &http.Transport{}
			*handler.Transport = *transport

			fixedURL, err := url.Parse(server.UpstreamProxy)
			if err != nil {
				glog.Fatalf("url.Parse(%#v) error: %+v", server.UpstreamProxy, err)
			}

			switch fixedURL.Scheme {
			case "http":
				handler.Transport.Proxy = http.ProxyURL(fixedURL)
				fallthrough
			default:
				dialer2, err := proxy.FromURL(fixedURL, dialer, nil)
				if err != nil {
					glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL.String(), err)
				}
				handler.Dial = dialer2.Dial
				handler.Transport.Dial = dialer2.Dial
			}
		}

		switch server.ProxyAuthMethod {
		case "pam":
			if _, err := exec.LookPath("python"); err != nil {
				glog.Fatalf("pam: exec.LookPath(\"python\") error: %+v", err)
			}
			handler.SimplePAM = &SimplePAM{
				CacheSize: 2048,
			}
		case "":
			break
		default:
			glog.Fatalf("unsupport proxy_auth_method(%+v)", server.ProxyAuthMethod)
		}

		httpSrv := &http.Server{
			Handler: handler,
		}

		glog.Infof("Yap %s ListenAndServe on %s\n", version, ln.Addr().String())
		go httpSrv.Serve(ln)
	}

	cancel := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(cancel, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <- cancel
		glog.Infof("Yap received exit signal: %s", sig)
		done <- true
	}()
	<- done
	glog.Info("Yap exited")
}

func loadConfigData(filename string) ([]byte, error) {
	var tomlData []byte
	var err error
	switch {
	case strings.HasPrefix(filename, "data:text/x-toml;base64,"):
		parts := strings.Split(filename, ",")
		tomlData, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			glog.Fatalf("base64.StdEncoding.DecodeString(%+v) error: %+v", parts[1], err)
		}
	case os.Getenv("YAP_CONFIG_URL") != "":
		filename = os.Getenv("YAP_CONFIG_URL")
		fallthrough
	case strings.HasPrefix(filename, "https://"):
		glog.Infof("http.Get(%+v) ...", filename)
		resp, err := http.Get(filename)
		if err != nil {
			glog.Fatalf("http.Get(%+v) error: %+v", filename, err)
		}
		defer resp.Body.Close()
		tomlData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			glog.Fatalf("ioutil.ReadAll(%+v) error: %+v", resp.Body, err)
		}
	case filename == "":
		if _, err := os.Stat("yap.user.toml"); err == nil {
			filename = "yap.user.toml"
		} else {
			filename = "yap.toml"
		}
		fallthrough
	default:
		tomlData, err = ioutil.ReadFile(filename)
		if err != nil {
			glog.Fatalf("ioutil.ReadFile(%+v) error: %+v", filename, err)
		}
	}
	return tomlData, err
}

func newDialer() *yaputil.Dialer {
	dialer := &yaputil.Dialer{
		Dialer: &net.Dialer{
			KeepAlive: 0,
			Timeout:   16 * time.Second,
			DualStack: true,
		},
		Resolver: &yaputil.Resolver{
			LRUCache:  lrucache.NewLRUCache(8 * 1024),
			BlackList: lrucache.NewLRUCache(1024),
			DNSExpiry: 8 * time.Hour,
		},
	}
	if ips, err := yaputil.LocalIPv4s(); err == nil {
		for _, ip := range ips {
			dialer.Resolver.BlackList.Set(ip.String(), struct{}{}, time.Time{})
		}
		for _, s := range []string{"127.0.0.1", "::1"} {
			dialer.Resolver.BlackList.Set(s, struct{}{}, time.Time{})
		}
	}
	return dialer
}

func loadHTTP2Handler(h *MultiSNHandler, config Config, transport *http.Transport, dialer *yaputil.Dialer, cm *CertManager) () {
	var err error
	for _, server := range config.HTTP2 {
		handler := &HTTP2Handler{
			ServerNames: server.ServerName,
			Transport:   transport,
		}

		if server.ProxyFallback != "" {
			handler.Fallback, err = url.Parse(server.ProxyFallback)
			if err != nil {
				glog.Fatalf("url.Parse(%+v) error: %+v", server.ProxyFallback, err)
			}
			handler.DisableProxy = server.DisableProxy
		}

		if server.UpstreamProxy != "" {
			handler.Transport = &http.Transport{}
			*handler.Transport = *transport

			fixedURL, err := url.Parse(server.UpstreamProxy)
			if err != nil {
				glog.Fatalf("url.Parse(%#v) error: %+v", server.UpstreamProxy, err)
			}

			switch fixedURL.Scheme {
			case "http":
				handler.Transport.Proxy = http.ProxyURL(fixedURL)
				fallthrough
			default:
				newDialer, err := proxy.FromURL(fixedURL, dialer, nil)
				if err != nil {
					glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL.String(), err)
				}
				handler.Dial = newDialer.Dial
				handler.Transport.Dial = newDialer.Dial
			}
		}

		switch server.ProxyAuthMethod {
		case "pam":
			if _, err := exec.LookPath("python"); err != nil {
				glog.Fatalf("pam: exec.LookPath(\"python\") error: %+v", err)
			}
			handler.SimplePAM = &SimplePAM{
				CacheSize: 2048,
			}
		case "":
			break
		default:
			glog.Fatalf("unsupport proxy_auth_method(%+v)", server.ProxyAuthMethod)
		}

		for _, serverName := range server.ServerName {
			cm.Add(serverName, server.CertFile, server.KeyFile, server.PEM, server.ClientAuthFile, server.ClientAuthPem)
			h.ServerNames = append(h.ServerNames, serverName)
			h.Handlers[serverName] = handler
		}
	}
}

func serveHTTP2(config Config, seen map[string]struct {}, srv *http.Server) {
	for _, server := range config.HTTP2 {
		network := server.Network
		if network == "" {
			network = "tcp"
		}
		addr := server.Listen
		// skip for same listen
		if _, ok := seen[network+":"+addr]; ok {
			continue
		}
		seen[network+":"+addr] = struct{}{}
		ln, err := net.Listen(network, addr)
		if err != nil {
			glog.Fatalf("Listen(%s) error: %s", addr, err)
		}
		glog.Infof("Yap %s ListenAndServe on %s\n", version, ln.Addr().String())
		go srv.Serve(tls.NewListener(TCPListener{ln.(*net.TCPListener)}, srv.TLSConfig))
	}
}
