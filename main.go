// Copyright 2017 Mathieu Lonjaret

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/mpl/basicauth"
	"github.com/mpl/simpletls"
)

const (
	idstring = "http://golang.org/pkg/http/#ListenAndServe"
)

var (
	host         = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	help         = flag.Bool("h", false, "show this help")
	flagUserpass = flag.String("userpass", "", "optional username:password protection")
	flagTLS      = flag.Bool("tls", false, `For https. If "key.pem" or "cert.pem" are not found in $HOME/keys/, in-memory self-signed are generated and used instead.`)
)

var (
	up   *basicauth.UserPass
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
			basicauth.SendUnauthorized(w, r, "showip")
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

	initUserPass()

	if !*flagTLS && *simpletls.FlagAutocert {
		*flagTLS = true
	}

	var err error
	var listener net.Listener
	if *flagTLS {
		listener, err = simpletls.Listen(*host)
	} else {
		listener, err = net.Listen("tcp", *host)
	}
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *host, err)
	}

	http.Handle("/recordip", makeHandler(recordRemoteAddrHandler))
	http.Handle("/", makeHandler(showipHandler))
	if err = http.Serve(listener, nil); err != nil {
		log.Fatalf("Error in http server: %v\n", err)
	}
}
