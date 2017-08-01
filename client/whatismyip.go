// Copyright 2017 Mathieu Lonjaret

package main

import (
	"crypto/tls"
	"flag"
	//	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

var (
	flagUsername = flag.String("user", "", "username")
	flagPassword = flag.String("pass", "", "password")
	flagInsecure = flag.Bool("insecure", false, "run with insecure TLS")
)

var (
	sleepTime = 5 * time.Minute
)

func main() {
	flag.Parse()
	first := true
	for {
		if !first {
			time.Sleep(sleepTime)
		}
		first = false
		req, err := http.NewRequest("GET", "https://granivo.re:9999/recordip", nil)
		if err != nil {
			log.Printf("could not prepare request: %v", err)
			continue
		}
		req.SetBasicAuth(*flagUsername, *flagPassword)
		cl := &http.Client{}
		if *flagInsecure {
			dialTLS := func(network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, &tls.Config{
					InsecureSkipVerify: true,
				})
			}
			cl.Transport = &http.Transport{
				DialTLS: dialTLS,
			}
		}
		resp, err := cl.Do(req)
		if err != nil {
			log.Printf("could not get ip: %v", err)
			continue
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			log.Printf("could not read ip: %v", err)
			continue
		}
		resp.Body.Close()
		log.Printf("Server recorded my address as: %v", string(data))
	}
}
