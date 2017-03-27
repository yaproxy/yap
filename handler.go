package yap

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/phuslu/glog"
	"github.com/yaproxy/yap/yaputil"
)

type FlushWriter struct {
	w io.Writer
}

func (fw FlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

type HTTPHandler struct {
	Dial func(network, address string) (net.Conn, error)
	*http.Transport
	*SimplePAM
}

func (h *HTTPHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var err error

	var paramsPreifx string = http.CanonicalHeaderKey("X-UrlFetch-")
	params := http.Header{}
	for key, values := range req.Header {
		if strings.HasPrefix(key, paramsPreifx) {
			params[key] = values
		}
	}

	for key := range params {
		req.Header.Del(key)
	}

	if h.SimplePAM != nil {
		auth := req.Header.Get("Proxy-Authorization")
		if auth == "" {
			h.ProxyAuthorizationReqiured(rw, req)
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 {
			switch parts[0] {
			case "Basic":
				if userpass, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
					parts := strings.Split(string(userpass), ":")
					username := parts[0]
					password := parts[1]

					if err := h.SimplePAM.Authenticate(username, password); err != nil {
						http.Error(rw, "403 Forbidden", http.StatusForbidden)
					}
				}
			default:
				glog.Errorf("Unrecognized auth type: %#v", parts[0])
				http.Error(rw, "403 Forbidden", http.StatusForbidden)
				return
			}
		}

		req.Header.Del("Proxy-Authorization")
	}

	if req.Method == http.MethodConnect {
		host, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
			port = "443"
		}

		glog.Infof("%s \"%s %s:%s %s\" - -", req.RemoteAddr, req.Method, host, port, req.Proto)

		dial := h.Dial
		if dial == nil {
			dial = h.Transport.Dial
		}

		conn, err := dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
			return
		}
		lconn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")

		defer lconn.Close()
		defer conn.Close()

		go yaputil.IOCopy(conn, lconn)
		yaputil.IOCopy(lconn, conn)

		return
	}

	if req.Host == "" {
		http.Error(rw, "400 Bad Request", http.StatusBadRequest)
		return
	}

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	if req.ContentLength == 0 {
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()
		req.Body = nil
	}

	glog.Infof("%s \"%s %s %s\" - -", req.RemoteAddr, req.Method, req.URL.String(), req.Proto)

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "Invaid DNS Record: ") {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
		} else {
			http.Error(rw, err.Error(), http.StatusBadGateway)
		}
		return
	}

	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)

	defer resp.Body.Close()

	var r io.Reader = resp.Body
	yaputil.IOCopy(rw, r)
}

func (h *HTTPHandler) ProxyAuthorizationReqiured(rw http.ResponseWriter, req *http.Request) {
	data := "Proxy Authentication Required"
	resp := &http.Response{
		StatusCode: http.StatusProxyAuthRequired,
		Header: http.Header{
			"Proxy-Authenticate": []string{"Basic realm=\"Proxy Authentication Required\""},
		},
		Request:       req,
		ContentLength: int64(len(data)),
		Body:          ioutil.NopCloser(strings.NewReader(data)),
	}
	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	yaputil.IOCopy(rw, resp.Body)
}

type HTTP2Handler struct {
	ServerNames  []string
	Fallback     *url.URL
	DisableProxy bool
	Dial         func(network, address string) (net.Conn, error)
	*http.Transport
	*SimplePAM
}

func (h *HTTP2Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var err error

	reqHostname := req.Host
	if host, _, err := net.SplitHostPort(req.Host); err == nil {
		reqHostname = host
	}

	var h2 bool = req.ProtoMajor == 2 && req.ProtoMinor == 0
	var isProxyRequest bool = !yaputil.ContainsString(h.ServerNames, reqHostname)

	var paramsPreifx string = http.CanonicalHeaderKey("X-UrlFetch-")
	params := http.Header{}
	for key, values := range req.Header {
		if strings.HasPrefix(key, paramsPreifx) {
			params[key] = values
		}
	}

	for key := range params {
		req.Header.Del(key)
	}

	if isProxyRequest && h.DisableProxy {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	var username, password string
	if isProxyRequest && h.SimplePAM != nil {
		auth := req.Header.Get("Proxy-Authorization")
		if auth == "" {
			h.ProxyAuthorizationReqiured(rw, req)
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 {
			switch parts[0] {
			case "Basic":
				if userpass, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
					parts := strings.Split(string(userpass), ":")
					username = parts[0]
					password = parts[1]

					if err := h.SimplePAM.Authenticate(username, password); err != nil {
						http.Error(rw, "403 Forbidden", http.StatusForbidden)
					}
				}
			default:
				glog.Errorf("Unrecognized auth type: %#v", parts[0])
				http.Error(rw, "403 Forbidden", http.StatusForbidden)
				return
			}
		}

		req.Header.Del("Proxy-Authorization")
	}

	if req.Method == http.MethodConnect {
		host, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
			port = "443"
		}

		glog.Infof("[%v 0x%04x %s] %s \"%s %s %s\" - -", req.TLS.ServerName, req.TLS.Version, username, req.RemoteAddr, req.Method, req.Host, req.Proto)

		dial := h.Dial
		if dial == nil {
			dial = h.Transport.Dial
		}

		conn, err := dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		var w io.Writer
		var r io.Reader

		if h2 {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
			}

			rw.WriteHeader(http.StatusOK)
			flusher.Flush()

			w = FlushWriter{rw}
			r = req.Body
		} else {
			hijacker, ok := rw.(http.Hijacker)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
				return
			}
			lconn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			defer lconn.Close()

			w = lconn
			r = lconn

			io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")
		}

		defer conn.Close()

		go yaputil.IOCopy(conn, r)
		yaputil.IOCopy(w, conn)

		return
	}

	if req.Host == "" {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	if req.ContentLength == 0 {
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()
		req.Body = nil
	}

	glog.Infof("[%v 0x%04x %s] %s \"%s %s %s\" - -", req.TLS.ServerName, req.TLS.Version, username, req.RemoteAddr, req.Method, req.URL.String(), req.Proto)

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	if h2 {
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.Proto = "HTTP/1.1"
	}

	if !isProxyRequest && h.Fallback != nil {
		if h.Fallback.Scheme == "file" {
			http.FileServer(http.Dir(h.Fallback.Path)).ServeHTTP(rw, req)
			return
		}
		req.URL.Scheme = h.Fallback.Scheme
		req.URL.Scheme = h.Fallback.Scheme
		req.URL.Host = h.Fallback.Host
		if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			xff := req.Header.Get("X-Forwarded-For")
			if xff == "" {
				req.Header.Set("X-Forwarded-For", ip)
			} else {
				req.Header.Set("X-Forwarded-For", xff+", "+ip)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Real-IP", ip)
		}
	}

	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "Invaid DNS Record: ") {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
		} else {
			http.Error(rw, err.Error(), http.StatusBadGateway)
		}
		return
	}

	if h2 {
		resp.Header.Del("Connection")
		resp.Header.Del("Keep-Alive")
	}

	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)

	defer resp.Body.Close()

	var r io.Reader = resp.Body
	yaputil.IOCopy(rw, r)
}

func (h *HTTP2Handler) ProxyAuthorizationReqiured(rw http.ResponseWriter, req *http.Request) {
	data := "Proxy Authentication Required"
	resp := &http.Response{
		StatusCode: http.StatusProxyAuthRequired,
		Header: http.Header{
			"Proxy-Authenticate": []string{"Basic realm=\"Proxy Authentication Required\""},
		},
		Request:       req,
		ContentLength: int64(len(data)),
		Body:          ioutil.NopCloser(strings.NewReader(data)),
	}
	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	yaputil.IOCopy(rw, resp.Body)
}


type Handler struct {
	ServerNames []string
	Handlers    map[string]http.Handler
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	handler, ok := h.Handlers[req.TLS.ServerName]
	if !ok {
		handler, ok = h.Handlers[h.ServerNames[0]]
		if !ok {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
	}
	handler.ServeHTTP(rw, req)
}