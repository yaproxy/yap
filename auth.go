package yap

import (
	"bytes"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	auth "github.com/abbot/go-http-auth"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
)

type compareFunc func(hashedPassword, password []byte) error

var (
	errMismatchedHashAndPassword = errors.New("mismatched hash and password")
	errUserNameNotFound          = errors.New("user name not found")
	errCredential                = errors.New("error credential")
	errCredentialFormat          = errors.New("error credential format")

	compareFuncs = []struct {
		prefix  string
		compare compareFunc
	}{
		{"", compareMD5HashAndPassword}, // default compareFunc
		{"{SHA}", compareShaHashAndPassword},
		// Bcrypt is complicated. According to crypt(3) from
		// crypt_blowfish version 1.3 (fetched from
		// http://www.openwall.com/crypt/crypt_blowfish-1.3.tar.gz), there
		// are three different has prefixes: "$2a$", used by versions up
		// to 1.0.4, and "$2x$" and "$2y$", used in all later
		// versions. "$2a$" has a known bug, "$2x$" was added as a
		// migration path for systems with "$2a$" prefix and still has a
		// bug, and only "$2y$" should be used by modern systems. The bug
		// has something to do with handling of 8-bit characters. Since
		// both "$2a$" and "$2x$" are deprecated, we are handling them the
		// same way as "$2y$", which will yield correct results for 7-bit
		// character passwords, but is wrong for 8-bit character
		// passwords. You have to upgrade to "$2y$" if you want sant 8-bit
		// character password support with bcrypt. To add to the mess,
		// OpenBSD 5.5. introduced "$2b$" prefix, which behaves exactly
		// like "$2y$" according to the same source.
		{"$2a$", bcrypt.CompareHashAndPassword},
		{"$2b$", bcrypt.CompareHashAndPassword},
		{"$2x$", bcrypt.CompareHashAndPassword},
		{"$2y$", bcrypt.CompareHashAndPassword},
	}
)

func compareShaHashAndPassword(hashedPassword, password []byte) error {
	d := sha1.New()
	d.Write(password)
	if subtle.ConstantTimeCompare(hashedPassword[5:], []byte(base64.StdEncoding.EncodeToString(d.Sum(nil)))) != 1 {
		return errMismatchedHashAndPassword
	}
	return nil
}

func compareMD5HashAndPassword(hashedPassword, password []byte) error {
	parts := bytes.SplitN(hashedPassword, []byte("$"), 4)
	if len(parts) != 4 {
		return errMismatchedHashAndPassword
	}
	magic := []byte("$" + string(parts[1]) + "$")
	salt := parts[2]
	if subtle.ConstantTimeCompare(hashedPassword, auth.MD5Crypt(password, salt, magic)) != 1 {
		return errMismatchedHashAndPassword
	}
	return nil
}

type Authenticator interface {
	Authenticate(username, password string) error
}

type HtpasswdAuth struct {
	CacheSize uint
	FilePath  string

	secrets auth.SecretProvider
	cache   lrucache.Cache
	once    sync.Once
}

func (h *HtpasswdAuth) init() {
	h.cache = lrucache.NewLRUCache(h.CacheSize)
	h.secrets = auth.HtpasswdFileProvider(h.FilePath)
}

func (h *HtpasswdAuth) Authenticate(username, password string) error {
	h.once.Do(h.init)
	credential := username + ":" + password

	if _, ok := h.cache.GetNotStale(credential); ok {
		return nil
	}

	secret := h.secrets(username, "")
	if secret == "" {
		return errUserNameNotFound
	}

	// default compare function: compareMD5HashAndPassword
	compare := compareFuncs[0].compare
	for _, cmp := range compareFuncs[1:] {
		if strings.HasPrefix(secret, cmp.prefix) {
			compare = cmp.compare
			break
		}
	}

	err := compare([]byte(secret), []byte(password))
	if err != nil {
		return err
	}

	h.cache.Set(credential, struct{}{}, time.Now().Add(2*time.Hour))
	return nil
}

type BuildInAuth struct {
	CacheSize  uint
	Credential string

	username string
	password string
	cache    lrucache.Cache
	once     sync.Once
}

func (b *BuildInAuth) init() {
	b.cache = lrucache.NewLRUCache(b.CacheSize)
	cred := strings.Split(b.Credential, ":")
	if len(cred) != 2 {
		panic(errCredentialFormat)
	}
	b.username = cred[0]
	b.password = cred[1]
}

func (b *BuildInAuth) Authenticate(username, password string) error {
	b.once.Do(b.init)
	if b.username == username && b.password == password {
		return nil
	}
	return errCredential
}

type SimplePAM struct {
	CacheSize uint

	path  string
	cache lrucache.Cache
	once  sync.Once
}

func (p *SimplePAM) init() {
	p.cache = lrucache.NewLRUCache(p.CacheSize)

	exe, err := os.Executable()
	if err != nil {
		glog.Fatalf("os.Executable() error: %+v", err)
	}

	p.path = filepath.Join(filepath.Dir(exe), "pwauth")
	if _, err := os.Stat(p.path); err != nil {
		glog.Fatalf("os.Stat(%#v) error: %+v", p.path, err)
	}

	if syscall.Geteuid() != 0 {
		glog.Warningf("Please run as root if you want to use pam auth")
	}
}

func (p *SimplePAM) Authenticate(username, password string) error {
	p.once.Do(p.init)

	credential := username + ":" + password

	if _, ok := p.cache.GetNotStale(credential); ok {
		return nil
	}

	cmd := exec.Command(p.path)
	cmd.Stdin = strings.NewReader(username + "\n" + password + "\n")
	err := cmd.Run()

	if err != nil {
		glog.Warningf("Authenticator: username=%v password=%v error: %+v", username, password, err)
		time.Sleep(time.Duration(5+rand.Intn(6)) * time.Second)
		return err
	}

	p.cache.Set(credential, struct{}{}, time.Now().Add(2*time.Hour))
	return nil
}
