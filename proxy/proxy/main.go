package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"sync/atomic"
	"time"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:8080", "listen host:port")
	statusPath = flag.String("status", "/data/local/tmp/proxy.status", "status file path")
	logPath    = flag.String("log", "/data/local/tmp/proxy.log", "request log path")
	certDir    = flag.String("cert-dir", "/data/local/tmp", "dir with ca.pem and ca-key.pem")
	targetPkg  = flag.String("target", "", "target package (info only)")
)

var (
	caCert *x509.Certificate
	caKey  interface{}

	rounds int64
	bytes  int64
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("proxy starting listen=%s target=%s", *listenAddr, *targetPkg)

	if err := loadCA(); err != nil {
		log.Fatalf("load CA failed: %v", err)
	}

	go statusLoop()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("listening on %s", *listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func loadCA() error {
	certPem, err := os.ReadFile(filepath.Join(*certDir, "ca.pem"))
	if err != nil {
		return fmt.Errorf("read ca.pem: %w", err)
	}
	keyPem, err := os.ReadFile(filepath.Join(*certDir, "ca-key.pem"))
	if err != nil {
		return fmt.Errorf("read ca-key.pem: %w", err)
	}

	cb, _ := pem.Decode(certPem)
	if cb == nil {
		return fmt.Errorf("ca.pem not valid PEM")
	}
	caCert, err = x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	kb, _ := pem.Decode(keyPem)
	if kb == nil {
		return fmt.Errorf("ca-key.pem not valid PEM")
	}
	if k, e := x509.ParsePKCS8PrivateKey(kb.Bytes); e == nil {
		caKey = k
	} else if k, e := x509.ParsePKCS1PrivateKey(kb.Bytes); e == nil {
		caKey = k
	} else if k, e := x509.ParseECPrivateKey(kb.Bytes); e == nil {
		caKey = k
	} else {
		return fmt.Errorf("unsupported key format")
	}

	log.Printf("CA loaded: CN=%s", caCert.Subject.CommonName)
	return nil
}

var certCache sync.Map

func getCert(host string) (*tls.Certificate, error) {
	if v, ok := certCache.Load(host); ok {
		return v.(*tls.Certificate), nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  priv,
	}
	certCache.Store(host, c)
	return c, nil
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func handleConn(client net.Conn) {
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(15 * time.Second))
	peek := make([]byte, 1)
	if _, err := io.ReadFull(client, peek); err != nil {
		return
	}
	client.SetReadDeadline(time.Time{})

	if peek[0] != 0x16 {
		handlePlain(client, peek)
		return
	}

	prefixed := &prefixConn{Conn: client, prefix: peek}
	cfg := &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			host := chi.ServerName
			if host == "" {
				host = "unknown.local"
			}
			c, err := getCert(host)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{*c},
				NextProtos:   []string{"http/1.1"},
			}, nil
		},
	}
	tlsConn := tls.Server(prefixed, cfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("tls handshake: %v", err)
		return
	}

	host := tlsConn.ConnectionState().ServerName
	if host == "" {
		host = "unknown"
	}

	serveHTTP(tlsConn, host, true)
}

func handlePlain(client net.Conn, firstByte []byte) {
	prefixed := &prefixConn{Conn: client, prefix: firstByte}
	br := bufio.NewReader(prefixed)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("plain read: %v", err)
		return
	}
	host := req.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	forward(client, req, host, false)
}

func serveHTTP(client net.Conn, host string, isTLS bool) {
	br := bufio.NewReader(client)
	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		client.SetReadDeadline(time.Time{})
		if !forward(client, req, host, isTLS) {
			return
		}
		req.Body.Close()
	}
}

func forward(w io.Writer, req *http.Request, host string, isTLS bool) bool {
	req.RequestURI = ""
	if req.URL.Host == "" {
		if isTLS {
			req.URL.Scheme = "https"
			req.URL.Host = host + ":443"
		} else {
			req.URL.Scheme = "http"
			req.URL.Host = host + ":80"
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		log.Printf("upstream %s %s: %v", req.Method, req.URL.String(), err)
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))

	atomic.AddInt64(&rounds, 1)
	atomic.AddInt64(&bytes, int64(len(body)))

	entry := fmt.Sprintf("[%s] %s %s%s -> %d (%dB) via=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		req.Method, req.URL.Host, req.URL.Path, resp.StatusCode, len(body), host)
	writeLog(entry)
	if looksTextual(body) {
		writeLog("  body: " + sanitize(string(body)) + "\n")
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Content-Encoding")
	if err := resp.Write(w); err != nil {
		log.Printf("write response: %v", err)
		return false
	}
	return true
}

func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	good := 0
	for _, r := range b {
		if (r >= 0x20 && r < 0x7F) || r == '\n' || r == '\r' || r == '\t' {
			good++
		}
	}
	return float64(good)/float64(len(b)) > 0.85
}

func sanitize(s string) string {
	if len(s) > 4096 {
		s = s[:4096] + "...[trunc]"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func writeLog(line string) {
	f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

func statusLoop() {
	for {
		time.Sleep(1 * time.Second)
		content := fmt.Sprintf("rounds=%d\nbytes=%d\nstarted=%d\n",
			atomic.LoadInt64(&rounds),
			atomic.LoadInt64(&bytes),
			time.Now().UnixMilli())
		tmp := *statusPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0644); err == nil {
			os.Rename(tmp, *statusPath)
		}
	}
}
