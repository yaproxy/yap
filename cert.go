package yap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/glog"
	"github.com/yaproxy/yap/yaputil"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
	// FOR TLS 1.3
	//"github.com/derekparker/delve/pkg/config"
)

type CertManager struct {
	RejectNilSni bool

	hosts  []string
	certs  map[string]*tls.Certificate
	cpools map[string]*x509.CertPool
	ecc    *autocert.Manager
	rsa    *autocert.Manager
	cache  lrucache.Cache
}

func (cm *CertManager) Add(host string, certfile, keyfile string, pem string, cafile, capem string) error {
	var err error

	if cm.ecc == nil {
		cm.ecc = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("ecc"),
			HostPolicy: cm.HostPolicy,
		}
	}

	if cm.rsa == nil {
		cm.rsa = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("rsa"),
			HostPolicy: cm.HostPolicy,
			ForceRSA:   true,
		}
	}

	if cm.certs == nil {
		cm.certs = make(map[string]*tls.Certificate)
	}

	if cm.cpools == nil {
		cm.cpools = make(map[string]*x509.CertPool)
	}

	if cm.cache == nil {
		cm.cache = lrucache.NewLRUCache(128)
	}

	switch {
	case pem != "":
		cert, err := tls.X509KeyPair([]byte(pem), []byte(pem))
		if err != nil {
			return err
		}
		cm.certs[host] = &cert
	case certfile != "" && keyfile != "":
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return err
		}
		cm.certs[host] = &cert
	default:
		cm.certs[host] = nil
	}

	var asn1Data []byte = []byte(capem)

	if cafile != "" {
		if asn1Data, err = ioutil.ReadFile(cafile); err != nil {
			glog.Fatalf("ioutil.ReadFile(%#v) error: %+v", cafile, err)
		}
	}

	if len(asn1Data) > 0 {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return err
		}

		certPool := x509.NewCertPool()
		certPool.AddCert(cert)

		cm.cpools[host] = certPool
	}

	cm.hosts = append(cm.hosts, host)

	return nil
}

func (cm *CertManager) HostPolicy(_ context.Context, host string) error {
	if _, ok := cm.certs[host]; !ok {
		return errors.New("acme/autocert: host not configured")
	}
	return nil
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := cm.certs[hello.ServerName]
	if cert != nil {
		return cert, nil
	}

	if yaputil.HasECCCiphers(hello.CipherSuites) {
		cert, err := cm.ecc.GetCertificate(hello)
		switch {
		case cert != nil:
			return cert, nil
		case err != nil && strings.HasSuffix(hello.ServerName, ".acme.invalid"):
			break
		default:
			return nil, err
		}
	}

	return cm.rsa.GetCertificate(hello)
}

func (cm *CertManager) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello.ServerName == "" {
		if cm.RejectNilSni {
			hello.Conn.Close()
			return nil, nil
		}
		hello.ServerName = cm.hosts[0]
	}

	hasECC := yaputil.HasECCCiphers(hello.CipherSuites)

	cacheKey := hello.ServerName
	if !hasECC {
		cacheKey += ",rsa"
	}

	if v, ok := cm.cache.GetNotStale(cacheKey); ok {
		return v.(*tls.Config), nil
	}

	cert, err := cm.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	/*
	config := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		Max0RTTDataSize:          100 * 1024,
		Accept0RTTData:           true,
		AllowShortHeaders:        true,
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}
	*/
	config := &tls.Config{
		MaxVersion:               tls.VersionTLS12,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}

	if p, ok := cm.cpools[hello.ServerName]; ok {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = p
	}

	cm.cache.Set(cacheKey, config, time.Now().Add(2*time.Hour))

	return config, nil
}
