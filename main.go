// Copyright 2017 Mathieu Lonjaret

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mpl/basicauth"
	"golang.org/x/crypto/acme/autocert"
)

const (
	uploadform = "upload.html"
	idstring   = "http://golang.org/pkg/http/#ListenAndServe"
)

var (
	host         = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	help         = flag.Bool("h", false, "show this help")
	flagUserpass = flag.String("userpass", "", "optional username:password protection")
	flagTLS      = flag.Bool("tls", false, `For https. If "key.pem" or "cert.pem" are not found in $HOME/keys/, in-memory self-signed are generated and used instead.`)
	flagAutocert = flag.Bool("autocert", false, `Get https certificate from Let's Encrypt. Implies -tls=true. Obviously -host must contain a full qualified domain name. The cached certificate(s) will be in $HOME/keys/letsencrypt.cache.`)
	upload       = flag.Bool("upload", false, "enable uploading at /upload")
)

var (
	rootdir, _ = os.Getwd()
	up         *basicauth.UserPass
	tlsKey     = filepath.Join(os.Getenv("HOME"), "keys", "key.pem")
	tlsCert    = filepath.Join(os.Getenv("HOME"), "keys", "cert.pem")
	certCache  = filepath.Join(os.Getenv("HOME"), "keys", "letsencrypt.cache")
)

var (
	mu   sync.Mutex
	joIP = "NOPE"
)

func usage() {
	fmt.Fprintf(os.Stderr, "\t showip \n")
	flag.PrintDefaults()
	os.Exit(2)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e, ok := recover().(error); ok {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
		}()
		title := r.URL.Path
		w.Header().Set("Server", idstring)
		if isAllowed(r) {
			fn(w, r, title)
		} else {
			basicauth.SendUnauthorized(w, r, "simpleHttpd")
		}
	}
}

func isAllowed(r *http.Request) bool {
	if *flagUserpass == "" {
		return true
	}
	return up.IsAllowed(r)
}

func showipHandler(rw http.ResponseWriter, req *http.Request, url string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(rw, joIP)
}

func recordRemoteAddrHandler(rw http.ResponseWriter, req *http.Request, url string) {
	mu.Lock()
	defer mu.Unlock()
	joIP = req.RemoteAddr
	fmt.Fprintf(rw, joIP)
}

func genSelfTLS(certOut, keyOut io.Writer) error {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %s", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   *host,
			Organization: []string{*host},
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(),

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	log.Println("self-signed cert and key generated")
	return nil
}

func initUserPass() {
	if *flagUserpass == "" {
		return
	}
	var err error
	up, err = basicauth.New(*flagUserpass)
	if err != nil {
		log.Fatal(err)
	}
}

func setupTLS() (*tls.Config, error) {
	hostname := *host
	if strings.Contains(hostname, ":") {
		h, _, err := net.SplitHostPort(hostname)
		if err != nil {
			return nil, err
		}
		hostname = h
	}
	if *flagAutocert {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache(certCache),
		}
		return &tls.Config{
			GetCertificate: m.GetCertificate,
		}, nil
	}
	_, statErr1 := os.Stat(tlsCert)
	_, statErr2 := os.Stat(tlsKey)
	var cert tls.Certificate
	var err error
	if statErr1 == nil && statErr2 == nil {
		cert, err = tls.LoadX509KeyPair(tlsCert, tlsKey)
	} else {
		// generate in-memory certs
		var certMem, keyMem bytes.Buffer
		err = genSelfTLS(&certMem, &keyMem)
		if err != nil {
			return nil, err
		}
		cert, err = tls.X509KeyPair(certMem.Bytes(), keyMem.Bytes())
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS cert: %v", err)
	}
	return &tls.Config{
		Rand:         rand.Reader,
		Time:         time.Now,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert},
	}, nil

}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *help {
		usage()
	}

	nargs := flag.NArg()
	if nargs > 0 {
		usage()
	}

	listener, err := net.Listen("tcp", *host)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *host, err)
	}

	initUserPass()

	if !*flagTLS && *flagAutocert {
		*flagTLS = true
	}

	if *flagTLS {
		config, err := setupTLS()
		if err != nil {
			log.Fatalf("could not configure TLS connection: %v", err)
		}
		listener = tls.NewListener(listener, config)
	}

	http.Handle("/recordip", makeHandler(recordRemoteAddrHandler))
	http.Handle("/", makeHandler(showipHandler))
	if err = http.Serve(listener, nil); err != nil {
		log.Fatalf("Error in http server: %v\n", err)
	}
}
