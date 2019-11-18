package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quictrace"
	"golang.org/x/sync/errgroup"
)

const defaultPort = 5201

func parseBytes(s string) (int64, error) {
	unit := s[len(s)-1]
	if unit != 'k' && unit != 'm' && unit != 'g' {
		return strconv.ParseInt(s, 10, 64)
	}
	num, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil {
		return 0, err
	}
	switch unit {
	case 'k':
		return num * 1 << 10, nil
	case 'm':
		return num * 1 << 20, nil
	case 'g':
		return num * 1 << 30, nil
	default:
		panic("invalid unit")
	}
}

func main() {
	server := flag.Bool("s", false, "run as server")
	client := flag.String("c", "", "run as client: remote address")
	port := flag.Int("p", defaultPort, "port")
	seconds := flag.Int("t", 10, "time in seconds")
	trace := flag.Bool("trace", false, "enable quic-trace")
	bufferSizeStr := flag.String("l", "2k", "[kmg] length of the buffer to read and write")
	windowSizeStr := flag.String("w", "10m", "[kmg] receive window size (both stream and connection). Only valid for the server")
	numStreams := flag.Int("P", 20, "number of parallel client streams to run")
	flag.Parse()

	duration := time.Duration(*seconds) * time.Second
	bufferSize, err := parseBytes(*bufferSizeStr)
	if err != nil {
		log.Fatalf("Invalid buffer size: %s", err.Error())
	}
	windowSize, err := parseBytes(*windowSizeStr)
	if err != nil {
		log.Fatalf("Invalid window size: %s", err.Error())
	}

	if *server {
		err = runServer(*port, bufferSize, windowSize, *trace)
	} else {
		err = runClient(*client, *port, duration, *numStreams, bufferSize, *trace)
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

func exportTraces(tracer quictrace.Tracer) error {
	traces := tracer.GetAllTraces()
	if len(traces) != 1 {
		return errors.New("expected exactly one trace")
	}
	for _, trace := range traces {
		f, err := os.Create("trace.qtr")
		if err != nil {
			return err
		}
		if _, err := f.Write(trace); err != nil {
			return err
		}
		f.Close()
		fmt.Println("Wrote trace to", f.Name())
	}
	return nil
}

func runServer(port int, bufferSize int64, windowSize int64, trace bool) error {
	tlsConf, err := getTLSConfig()
	if err != nil {
		return err
	}
	tlsConf.NextProtos = []string{"qperf"}
	var tracer quictrace.Tracer
	if trace {
		tracer = quictrace.NewTracer()
	}
	ln, err := quic.ListenAddr(
		fmt.Sprintf("0.0.0.0:%d", port),
		tlsConf,
		&quic.Config{
			MaxReceiveStreamFlowControlWindow:     uint64(windowSize),
			MaxReceiveConnectionFlowControlWindow: uint64(windowSize),
			QuicTracer:                            tracer,
		},
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
				n, err := io.CopyN(ioutil.Discard, str, int64(bufferSize))
				bc.Add(int(n))
				if err != nil {
					return err
				}
			}
		})
	}

	err = g.Wait()
	if trace {
		if err := exportTraces(tracer); err != nil {
			return err
		}
	}
	return err
}

func runClient(address string, port int, duration time.Duration, numStreams int, bufferSize int64, trace bool) error {
	fmt.Printf("Connecting to host %s, port %d\n", address, port)
	var tracer quictrace.Tracer
	if trace {
		tracer = quictrace.NewTracer()
	}
	sess, err := quic.DialAddr(
		fmt.Sprintf("%s:%d", address, port),
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"qperf"},
		},
		&quic.Config{
			MaxIncomingUniStreams: 1000,
			QuicTracer:            tracer,
		},
	)
	if err != nil {
		return err
	}

	timer := time.AfterFunc(duration, func() {
		sess.Close()
	})
	defer timer.Stop()

	var bc bandwidthCounter
	go bc.Run(sess.Context().Done())

	var g errgroup.Group
	data := make([]byte, bufferSize)
	for i := 0; i < numStreams; i++ {
		str, err := sess.OpenUniStream()
		if err != nil {
			return err
		}
		g.Go(func() error {
			for {
				n, err := str.Write(data)
				bc.Add(n)
				if err != nil {
					return err
				}
			}
		})
	}

	err = g.Wait()
	if trace {
		if err := exportTraces(tracer); err != nil {
			return err
		}
	}
	return err
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
