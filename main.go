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
	"math"
	"math/big"
	"net"
	"sync/atomic"
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

func humanizeBytes(s uint64) string {
	return humanateBytes(s, []string{"B", "kB", "MB", "GB", "TB", "PB", "EB"})
}

func humanizeBits(s uint64) string {
	return humanateBytes(s, []string{"Bits", "kBits", "MBits", "GBits", "TBits", "PBits", "EBits"})
}

// see https://github.com/dustin/go-humanize/blob/master/bytes.go
func humanateBytes(s uint64, sizes []string) string {
	const base = 1000
	if s < 10 {
		return fmt.Sprintf("%d B", s)
	}
	e := math.Floor(math.Log(float64(s)) / math.Log(base))
	suffix := sizes[int(e)]
	val := math.Floor(float64(s)/math.Pow(base, e)*10+0.5) / 10
	f := "%.2f %s"
	if val < 10 {
		f = "%.2f %s"
	}

	return fmt.Sprintf(f, val, suffix)
}

type bandwidthCounter struct {
	startTime  time.Time
	lastReport time.Time

	total   uint64
	counter uint64 // to be used as an atomic
}

func (c *bandwidthCounter) Add(n int) {
	atomic.AddUint64(&c.total, uint64(n))
	atomic.AddUint64(&c.counter, uint64(n))
}

func (c *bandwidthCounter) print(start, end time.Duration, n uint64) {
	dur := end - start
	bw := 8 * uint64(float64(n)/dur.Seconds())
	fmt.Printf(" %.2f-%.2f\tsec\t%s\t%s/sec\n", start.Seconds(), end.Seconds(), humanizeBytes(n), humanizeBits(bw))
}

func (c *bandwidthCounter) Run(done <-chan struct{}) {
	now := time.Now()
	c.startTime = now
	c.lastReport = now

	fmt.Println("Interval\t\tTransfer\tBitrate")

	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-done:
			fmt.Println("- - - - - - - - - - - - - - - - - - - - - - - - -")
			fmt.Println("Interval\t\tTransfer\tBitrate")
			c.print(0, time.Since(c.startTime), atomic.LoadUint64(&c.total))
			return
		case <-ticker.C:
			now := time.Now()
			n := atomic.SwapUint64(&c.counter, 0)
			c.print(c.lastReport.Sub(c.startTime), now.Sub(c.startTime), n)
			c.lastReport = now
		}
	}
}

func (c *bandwidthCounter) FinalReport() (startTime time.Time, n uint64) {
	return c.startTime, atomic.LoadUint64(&c.counter)
}

func runServer(port int, duration time.Duration) error {
	tlsConf, err := getTLSConfig()
	if err != nil {
		return err
	}
	tlsConf.NextProtos = []string{"qperf"}
	ln, err := quic.ListenAddr(
		fmt.Sprintf("0.0.0.0:%d", port),
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
	fmt.Printf("Accepted connection from %s\n", raddr.(*net.UDPAddr).String())

	timer := time.AfterFunc(duration, func() {
		sess.Close()
	})
	defer timer.Stop()

	var g errgroup.Group
	var data [1 << 12]byte // 4 kbyte
	var bc bandwidthCounter
	go bc.Run(sess.Context().Done())

	for i := 0; i < numStreams; i++ {
		str, err := sess.OpenUniStream()
		if err != nil {
			return err
		}
		g.Go(func() error {
			for {
				n, err := str.Write(data[:])
				bc.Add(n)
				if err != nil {
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
		&quic.Config{MaxIncomingUniStreams: 1000},
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

	var bc bandwidthCounter
	go bc.Run(sess.Context().Done())

	var g errgroup.Group
	for {
		str, err := sess.AcceptUniStream(context.Background())
		if err != nil {
			break
		}

		g.Go(func() error {
			for {
				n, err := io.CopyN(ioutil.Discard, str, 1<<9)
				bc.Add(int(n))
				if err != nil {
					return err
				}
			}
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
