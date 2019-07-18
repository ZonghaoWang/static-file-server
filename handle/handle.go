package handle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	// These assignments are for unit testing.
	listenAndServe    = http.ListenAndServe
	listenAndServeTLS = http.ListenAndServeTLS
	setHandler        = http.HandleFunc
	sign			  = "megvii"
	publicKey = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMZ25lt7KbsuXJtiRqFYJeRoRf6BWZonlHYonIlOUQ/d58QL9gC/qzmH
IVkl6bNIMFp//Xjnfb4Sv6Lr7Rxab0PUNMND3N4fGcXOtBif2asS1aXWJ+UX8ofA
8eGrMNX9sCbGRFCYam+g6fYR8kmu8b0xhqnca7DMUrjCuv3JswHtAgMBAAE=
-----END RSA PUBLIC KEY-----
`)
	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICYgIBAAKBgQDGduZbeym7LlybYkahWCXkaEX+gVmaJ5R2KJyJTlEP3efEC/YA
v6s5hyFZJemzSDBaf/14532+Er+i6+0cWm9D1DTDQ9zeHxnFzrQYn9mrEtWl1ifl
F/KHwPHhqzDV/bAmxkRQmGpvoOn2EfJJrvG9MYap3GuwzFK4wrr9ybMB7QIDAQAB
AoGBALZbZgrEvnGJhfoYcQGrdxXKYhYaUHR+zcFMS5k2ZvGHWoAe5WmGtBPmAFRj
q7raJ+PgGs1PF5DgtUlEMfwYhtMWoyckFy7emYTy999vC/BesBLZK1+ShWIYxCrF
B9cDbXgFcEA44CPTrsGSnZjw0Ry1WABMMci5qIApW3i+hW9BAkUA7+0DRu9ChUhD
YOJgQSjHRw0FtKxuMa4qT/OETpbmZ4c5ztjprU0E/HQjuIrarCWTbXM7L2IrrK5r
o+szsE/+zkrITokCPQDTwseTjoJHgzGy4cmVTQXPTyRkehRp2y6ojwY3KOI1d6BI
ZUse+G4atOQEyXPiFfamIhHgpJITn8vJX0UCRQDbr0GY6esW7xwC0kUgZJ5TSHE5
BcnAY6EKpAc5jqJZmVAtPiB5NlSidBVhHIMtrRpY1XIT6OfkrbCR3wLtJdJCQec3
QQI8ZIjSy4Ea5OyqSazcUV+R5IxEUNeMnX0Lt8a/QqzMSGoU1IoSkg+L5m3+2y7x
L2MSCGmgZzB6kYqJ636pAkUAt9B/pEGS+Ck/oDQV+8d6d9bJPklGNVgn5I08x7ld
lOSMbnqyvfIYqzzdBUWZEMAoyPkhJ4NfwS9QrU/5X7V1hRnBJUg=
-----END RSA PRIVATE KEY-----
`)
)

var (
	server http.Server
)

// ListenerFunc accepts the {hostname:port} binding string required by HTTP
// listeners and the handler (router) function and returns any errors that
// occur.
type ListenerFunc func(string, http.HandlerFunc) error

// FileServerFunc is used to serve the file from the local file system to the
// requesting client.
type FileServerFunc func(http.ResponseWriter, *http.Request, string)

// WithReferrers returns a function that evaluates the HTTP 'Referer' header
// value and returns HTTP error 403 if the value is not found in the whitelist.
// If one of the whitelisted referrers are an empty string, then it is allowed
// for the 'Referer' HTTP header key to not be set.
func WithReferrers(serveFile FileServerFunc, referrers []string) FileServerFunc {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		if !validReferrer(referrers, r.Referer()) {
			http.Error(
				w,
				fmt.Sprintf("Invalid source '%s'", r.Referer()),
				http.StatusForbidden,
			)
			return
		}
		serveFile(w, r, name)
	}
}

func ProcessDecrypter(serveFile FileServerFunc) FileServerFunc {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		timeStart := time.Now()
		if r.URL.RawQuery == "" {
			log.Println("empty query")
			return
		}
		querys := r.URL.Query()
		timeArgs, exist := querys["time"]
		if !exist || len(timeArgs) == 0 {
			log.Println("time not in args")
			return
		}
		t, err := strconv.Atoi(timeArgs[0])
		if err != nil {
			log.Printf("time parse error, err = %v", err)
			return
		}
		if time.Now().Unix() - int64(t) > 300 || time.Now().Unix() + 50 < int64(t) {
			log.Println("timestamp expired")
			return
		}
		signatureArgs, exist := querys["signature"]
		if !exist || len(signatureArgs) == 0 {
			log.Println("signature not in args")
			return
		}
		decodeLen := hex.DecodedLen(len(signatureArgs[0]))
		signature := make([]byte, decodeLen)
		_, err = hex.Decode(signature, []byte(signatureArgs[0]))
		if err != nil {
			log.Println("hex decode error")
			return
		}
		block, _ := pem.Decode(privateKey)
		if block == nil {
			log.Println("private key error!")
			return
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Println("parse PKCS1 format error")
			return
		}
		cypherStr, err := rsa.DecryptPKCS1v15(rand.Reader, priv, signature)
		if err != nil {
			log.Printf("decrypt error, err = %+v", err)
			return
		}
		cypherArray := strings.Split(string(cypherStr), "&")
		if len(cypherArray) == 1 {
			log.Println("decode args length is 1")
			return
		}
		for _, cypher := range cypherArray {
			if strings.Contains(cypher, "sign") && strings.Contains(cypher, sign) {
				log.Printf("request come from %s\n", sign)
				serveFile(w, r, name)
				log.Printf("time cost is %v\n", time.Now().Sub(timeStart))
			}
		}
		return
	}
}

// WithLogging returns a function that logs information about the request prior
// to serving the requested file.
func WithLogging(serveFile FileServerFunc) FileServerFunc {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		referer := r.Referer()
		if 0 == len(referer) {
			log.Printf(
				"REQ from '%s': %s %s %s%s -> %s\n",
				r.RemoteAddr,
				r.Method,
				r.Proto,
				r.Host,
				r.URL.Path,
				name,
			)
		} else {
			log.Printf(
				"REQ from '%s' (REFERER: '%s'): %s %s %s%s -> %s\n",
				r.RemoteAddr,
				referer,
				r.Method,
				r.Proto,
				r.Host,
				r.URL.Path,
				name,
			)
		}
		serveFile(w, r, name)
	}
}

// Basic file handler servers files from the passed folder.
func Basic(serveFile FileServerFunc, folder string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serveFile(w, r, folder+r.URL.Path)
	}
}

// Prefix file handler is an alternative to Basic where a URL prefix is removed
// prior to serving a file (http://my.machine/prefix/file.txt will serve
// file.txt from the root of the folder being served (ignoring 'prefix')).
func Prefix(serveFile FileServerFunc, folder, urlPrefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, urlPrefix) {
			http.NotFound(w, r)
			return
		}
		serveFile(w, r, folder+strings.TrimPrefix(r.URL.Path, urlPrefix))
	}
}

// IgnoreIndex wraps an HTTP request. In the event of a folder root request,
// this function will automatically return 'NOT FOUND' as opposed to default
// behavior where the index file for that directory is retrieved.
func IgnoreIndex(serve http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		serve(w, r)
	}
}

// Listening function for serving the handler function.
func Listening() ListenerFunc {
	return func(binding string, handler http.HandlerFunc) error {
		setHandler("/", handler)
		return listenAndServe(binding, nil)
	}
}

// TLSListening function for serving the handler function with encryption.
func TLSListening(tlsCert, tlsKey string) ListenerFunc {
	return func(binding string, handler http.HandlerFunc) error {
		setHandler("/", handler)
		return listenAndServeTLS(binding, tlsCert, tlsKey, nil)
	}
}

// validReferrer returns true if the passed referrer can be resolved by the
// passed list of referrers.
func validReferrer(s []string, e string) bool {
	// Whitelisted referer list is empty. All requests are allowed.
	if 0 == len(s) {
		return true
	}

	for _, a := range s {
		// Handle blank HTTP Referer header, if configured
		if a == "" {
			if e == "" {
				return true
			}
			// Continue loop (all strings start with "")
			continue
		}

		// Compare header with allowed prefixes
		if strings.HasPrefix(e, a) {
			return true
		}
	}
	return false
}
