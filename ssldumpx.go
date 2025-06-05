// ssldumpx.go
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP     string
	Domains []string
	Wildcards []string
}

var (
	showHelp   = flag.Bool("help", false, "Show help message")
	wildOnly   = flag.Bool("wild-only", false, "Only print wildcard domains (*.example.com)")
	nowild     = flag.Bool("no-wild", false, "Only print non-wildcard domains")
	allDomains = flag.Bool("all", false, "Print all domains (wildcards and normal)")
	silent     = flag.Bool("silent", false, "Print only domains (no metadata)")
	uniq       = flag.Bool("uniq", false, "Only print unique domains")
	threads    = flag.Int("threads", 100, "Number of concurrent workers")
	timeout    = flag.Duration("timeout", 4*time.Second, "Timeout for TLS connection")
)

func isDomainValid(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	valid := regexp.MustCompile(`^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$`)
	return valid.MatchString(s)
}

func cleanTarget(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.Split(s, "/")[0]
	return s
}

func grabCert(ip string) (*Result, error) {
	dialer := &net.Dialer{Timeout: *timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	all := append(cert.DNSNames, cert.Subject.CommonName)
	res := &Result{IP: ip}

	for _, d := range all {
		d = strings.ToLower(strings.TrimSpace(d))
		if !isDomainValid(d) {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			res.Wildcards = append(res.Wildcards, d)
		} else {
			res.Domains = append(res.Domains, d)
		}
	}
	return res, nil
}

func printDomain(domain string, seen *sync.Map) {
	if *uniq {
		if _, loaded := seen.LoadOrStore(domain, true); loaded {
			return
		}
	}
	fmt.Println(domain)
}

func printResult(r *Result, seen *sync.Map) {
	if *wildOnly {
		for _, d := range r.Wildcards {
			printDomain(d, seen)
		}
		return
	}
	if *nowild {
		for _, d := range r.Domains {
			printDomain(d, seen)
		}
		return
	}
	if *allDomains || *silent {
		for _, d := range append(r.Domains, r.Wildcards...) {
			printDomain(d, seen)
		}
		return
	}

	// default: show help
	flag.Usage()
	os.Exit(0)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ssldumpx - Extract domains from SSL certificates
- S S L ~ DUMP (X) - ssldumpx -
Author: rootface
Github: 0xrootface
Usage:
  ssldumpx [flags] < IPs/domains from stdin or args >
Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showHelp || (!*wildOnly && !*nowild && !*allDomains && !*silent) {
		flag.Usage()
		return
	}

	seen := &sync.Map{}
	targets := make(chan string, *threads)
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				res, err := grabCert(t)
				if err == nil {
					printResult(res, seen)
				}
			}
		}()
	}

	if flag.NArg() > 0 {
		for _, arg := range flag.Args() {
			t := cleanTarget(arg)
			if t != "" {
				targets <- t
			}
		}
		close(targets)
		wg.Wait()
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			t := cleanTarget(scanner.Text())
			if t != "" {
				targets <- t
			}
		}
		close(targets)
	}()

	wg.Wait()
}
