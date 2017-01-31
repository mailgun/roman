package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	golang_acme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/mailgun/roman"
	"github.com/mailgun/roman/acme"
	"github.com/mailgun/roman/challenge"
)

func readConfiguration(configurationPath string) (*challenge.Route53, error) {
	file, err := os.Open(configurationPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var c challenge.Route53

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "=")
		keyName := strings.Trim(parts[0], " ")
		keyValue := strings.Trim(parts[1], " ")

		switch keyName {
		case "Route53-Region":
			c.Region = keyValue
		case "Route53-AccessKeyID":
			c.AccessKeyID = keyValue
		case "Route53-SecretAccessKey":
			c.SecretAccessKey = keyValue
		case "Route53-HostedZoneID":
			c.HostedZoneID = keyValue
		case "Route53-HostedDomainName":
			c.HostedDomainName = keyValue
		case "Route53-WaitForSync":
			waitForSync, err := strconv.ParseBool(keyValue)
			if err != nil {
				return nil, err
			}
			c.WaitForSync = waitForSync
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method: %v; URL: %v; ContentLength: %v\n", r.Method, r.URL, r.ContentLength)
	fmt.Fprintf(w, "Method: %v; URL: %v, ContentLength: %v\n", r.Method, r.URL, r.ContentLength)
}

func main() {
	// parse flags
	var cachePath = flag.String("cache-path", ".", "path to certificate cache")
	var configurationPath = flag.String("configuration-path", ".roman.configuration", "path to roman configuration file")
	var hostname = flag.String("hostname", "", "hostname for certificate to request")
	var debugMode = flag.Bool("debug-mode", true, "in debug mode, primer reaches out debug LE servers")
	var hostport = flag.String("hostport", ":443", "hostname:port that the local server should listen on")
	var renewBefore = flag.Duration("renew-before", 30*24*time.Hour, "how long before certificate expiration a new certificate will be requested")

	flag.Parse()

	// hostname is always required!
	if *hostname == "" {
		fmt.Printf("Unable to read in hostname\n")
		os.Exit(255)
	}

	// read in configuration from disk
	performer, err := readConfiguration(*configurationPath)
	if err != nil {
		fmt.Printf("Unable to read configuration: %v\n", err)
		os.Exit(255)
	}

	// we're always in debug mode, force users to contact production acme servers when they are ready
	leDirectory := acme.LetsEncryptStaging
	if *debugMode == false {
		leDirectory = acme.LetsEncryptProduction
	}

	// create a certificate manager
	m := roman.CertificateManager{
		ACMEClient: &acme.Client{
			Directory:          leDirectory,
			AgreeTOS:           golang_acme.AcceptTOS,
			Email:              "foo@example.com",
			ChallengePerformer: performer,
		},
		Cache:       autocert.DirCache(*cachePath),
		KnownHosts:  []string{*hostname},
		RenewBefore: *renewBefore,
	}

	fmt.Printf("Roman: Starting CertificateManager...\n")

	// start the certificate manager, this is a blocking call that
	// ensures that certificates are ready before the server starts
	// accepting connections
	err = m.Start()
	if err != nil {
		fmt.Printf("Unable to start CertificateManager: %v", err)
		os.Exit(255)
	}

	fmt.Printf("Roman: CertificateManager started, starting web server and listening on %v...\n", *hostport)

	// define a handler that will log every request
	http.HandleFunc("/", handler)

	// start the http server a *tls.Config that uses the certificate manager
	// to obtain certificates
	s := &http.Server{
		Addr:      *hostport,
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	err = s.ListenAndServeTLS("", "")
	fmt.Printf("Roman: Unable to start web server.\n")
}
