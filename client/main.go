package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

func doAuthentication(ctx context.Context, conn *quic.Conn, subdomain string, password string) error {
	authStream, err := conn.NewSendOnlyStream(ctx)
	if err != nil {
		return fmt.Errorf("error in NewSendOnlyStream: %w", err)
	}
	defer authStream.Close()

	_, err = authStream.Write(slices.Concat([]byte(subdomain), []byte(":"), []byte(password)))
	if err != nil {
		return fmt.Errorf("error in Write: %w", err)
	}

	return nil
}

func handleStream(stream *quic.Stream, originAddress string) {
	defer stream.Close()

	slog.Info("Accepted stream")

	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		slog.Error("Error in ReadRequest", slog.Any("error", err))
		return
	}

	request.RequestURI = ""
	request.URL.Scheme = "http"
	request.URL.Host = originAddress
	request.Host = ""

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		slog.Error("Error in Do", slog.Any("error", err))
		return
	}

	err = response.Write(stream) // Write closes the response body
	if err != nil {
		slog.Error("Error in Write", slog.Any("error", err))
		return
	}
}

func runClient(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, proxyAddress string, originAddress string, subdomain string, password string) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Client is shutting down")

	clientEndpoint, err := quic.Listen("udp", ":0", nil)
	if err != nil {
		slog.Error("Error in Listen", slog.Any("error", err))
		return
	}
	defer clientEndpoint.Close(ctx)

	conn, err := clientEndpoint.Dial(ctx, "udp", proxyAddress, &quic.Config{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		KeepAlivePeriod: 15 * time.Second,
		// QLogLogger: slog.Default(),
	})
	if err != nil {
		slog.Error("Error in Dial", slog.Any("error", err))
		return
	}
	defer conn.Close()

	slog.Info("Dialed proxy", slog.String("connection", conn.String()))

	err = doAuthentication(ctx, conn, subdomain, password)
	if err != nil {
		slog.Error("Error in doAuthentication", slog.Any("error", err))
		return
	}

	slog.Info("Authenticated", slog.String("connection", conn.String()))

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			slog.Error("Error in AcceptStream", slog.Any("error", err))
			return
		}

		go handleStream(stream, originAddress)
	}
}

func main() {
	var PROXY_ADDRESS string
	var ORIGIN_ADDRESS string
	var SUBDOMAIN string
	var PASSWORD string

	flag.StringVar(&PROXY_ADDRESS, "proxy-address", "", "proxy address with host and port")
	flag.StringVar(&ORIGIN_ADDRESS, "origin-address", "", "origin address")
	flag.StringVar(&SUBDOMAIN, "subdomain", "", "subdomain name")
	flag.StringVar(&PASSWORD, "password", "", "password")
	flag.Parse()

	if PROXY_ADDRESS == "" || ORIGIN_ADDRESS == "" || SUBDOMAIN == "" || PASSWORD == "" {
		flag.Usage()
		return
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	shutdownWaitGroup := &sync.WaitGroup{}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	shutdownWaitGroup.Add(1)
	go runClient(ctx, shutdownWaitGroup, cancelCtx, PROXY_ADDRESS, ORIGIN_ADDRESS, SUBDOMAIN, PASSWORD)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-ctx.Done():
	case <-quit:
		cancelCtx()
	}

	shutdownWaitGroup.Wait()
}
