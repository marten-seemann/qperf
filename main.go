package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"golang.org/x/sync/errgroup"
)

const (
	numStreams  = 20
	defaultPort = 5201
)

func main() {
	server := flag.Bool("s", false, "run as server")
	client := flag.String("c", "", "run as client: remote address")
	port := flag.Int("p", defaultPort, "port")
	seconds := flag.Int("t", 10, "time in seconds")
	flag.Parse()

	duration := time.Duration(*seconds) * time.Second

	var err error
	if *server {
		err = runServer(*port, duration)
	} else {
		err = runClient(*client, *port, duration)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func runServer(port int, duration time.Duration) error {
	tlsConf, err := getTLSConfig()
	if err != nil {
		return err
	}
	tlsConf.NextProtos = []string{"qperf"}
	ln, err := quic.ListenAddr(
		fmt.Sprintf("localhost:%d", port),
		tlsConf,
		&quic.Config{},
	)
	if err != nil {
		return err
	}
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("Server listening on %d\n", port)
	fmt.Println("-----------------------------------------------------------")
	sess, err := ln.Accept(context.Background())
	if err != nil {
		return err
	}
	raddr := sess.RemoteAddr()
	fmt.Printf("Accepted connection from %s", raddr.(*net.UDPAddr).String())

	timer := time.AfterFunc(duration, func() {
		sess.Close()
	})
	defer timer.Stop()

	var g errgroup.Group
	var data [1 << 12]byte // 4 kbyte
	for i := 0; i < numStreams; i++ {
		str, err := sess.OpenUniStream()
		if err != nil {
			return err
		}
		g.Go(func() error {
			for {
				if _, err := str.Write(data[:]); err != nil {
					return err
				}
			}
		})
	}
	return g.Wait()
}

func runClient(address string, port int, duration time.Duration) error {
	fmt.Printf("Connecting to host %s, port %d\n", address, port)
	sess, err := quic.DialAddr(
		fmt.Sprintf("%s:%d", address, port),
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"qperf"},
		},
		&quic.Config{},
	)
	if err != nil {
		return err
	}
	raddr := sess.RemoteAddr()
	fmt.Printf("Accepted connection from %s\n", raddr.(*net.UDPAddr).String())

	timer := time.AfterFunc(duration, func() {
		sess.Close()
	})
	defer timer.Stop()

	var g errgroup.Group
	for {
		str, err := sess.AcceptUniStream(context.Background())
		if err != nil {
			break
		}

		g.Go(func() error {
			_, err := io.Copy(ioutil.Discard, str)
			return err
		})
	}

	return g.Wait()
}

func getTLSConfig() (*tls.Config, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			{PrivateKey: rootKey, Certificate: [][]byte{certDER}},
		},
	}, nil
}
