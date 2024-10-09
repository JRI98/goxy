package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"golang.org/x/net/quic"
)

type SubdomainInfo struct {
	mu sync.RWMutex

	secret            string
	originConnections []*quic.Conn
	timeWhenNoOrigin  time.Time
}

// TODO: store in SQLite
type SubdomainsStore struct {
	mu sync.RWMutex

	subdomainNameToInfo map[string]*SubdomainInfo
}

func getSubdomainInfo(subdomainsStore *SubdomainsStore, subdomainName string) *SubdomainInfo {
	subdomainsStore.mu.RLock()
	defer subdomainsStore.mu.RUnlock()

	return subdomainsStore.subdomainNameToInfo[subdomainName]
}

func insertSubdomainInfo(subdomainsStore *SubdomainsStore, subdomainName string, info *SubdomainInfo) (inserted bool) {
	subdomainsStore.mu.Lock()
	defer subdomainsStore.mu.Unlock()

	if _, exists := subdomainsStore.subdomainNameToInfo[subdomainName]; exists {
		return false
	}

	subdomainsStore.subdomainNameToInfo[subdomainName] = info

	return true
}

func subdomainGetRandomConnection(subdomainsStore *SubdomainsStore, subdomainName string) *quic.Conn {
	info := getSubdomainInfo(subdomainsStore, subdomainName)
	if info == nil {
		return nil
	}

	info.mu.RLock()
	defer info.mu.RUnlock()

	if len(info.originConnections) == 0 {
		return nil
	}

	// TODO: allow configuring the distribution: random, round robin, least connections

	return info.originConnections[rand.Intn(len(info.originConnections))]
}

func subdomainAddConnectionIfSecret(subdomainsStore *SubdomainsStore, subdomainName string, secret string, conn *quic.Conn) error {
	info := getSubdomainInfo(subdomainsStore, subdomainName)
	if info == nil {
		info = &SubdomainInfo{
			secret:            secret,
			originConnections: []*quic.Conn{conn},
			timeWhenNoOrigin:  time.Time{},
		}

		inserted := insertSubdomainInfo(subdomainsStore, subdomainName, info)
		if !inserted {
			// There was a race condition. Try again
			return subdomainAddConnectionIfSecret(subdomainsStore, subdomainName, secret, conn)
		}
		return nil
	}

	info.mu.Lock()
	defer info.mu.Unlock()

	if info.secret != secret {
		return errors.New("invalid secret for subdomain")
	}

	info.originConnections = append(info.originConnections, conn)
	info.timeWhenNoOrigin = time.Time{}

	return nil
}

func subdomainRemoveConnection(subdomainsStore *SubdomainsStore, subdomainName string, conn *quic.Conn) error {
	subdomainsStore.mu.RLock()
	defer subdomainsStore.mu.RUnlock()

	info := subdomainsStore.subdomainNameToInfo[subdomainName]
	if info == nil {
		return errors.New("connection not found for subdomain")
	}

	info.mu.Lock()
	defer info.mu.Unlock()

	for i, c := range info.originConnections {
		if c == conn {
			info.originConnections = slices.Delete(info.originConnections, i, i+1)
			break
		}
	}

	if len(info.originConnections) == 0 {
		info.timeWhenNoOrigin = time.Now()
	}

	return nil
}

var RESERVED_SUBDOMAINS = []string{"admin", "beta", "blog", "ftp", "imap", "mail", "pop", "pop3", "sftp", "smtp", "ssl", "www"}

func isValidSubdomainName(subdomainName string) bool {
	if slices.Contains(RESERVED_SUBDOMAINS, subdomainName) {
		return false
	}

	if len(subdomainName) < 3 || len(subdomainName) > 63 {
		return false
	}

	if subdomainName[0] == '-' || subdomainName[len(subdomainName)-1] == '-' {
		return false
	}

	for _, char := range subdomainName {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' {
			return false
		}
	}

	return true
}

func doAuthentication(ctx context.Context, conn *quic.Conn) (string, string, error) {
	authStream, err := conn.AcceptStream(ctx)
	if err != nil {
		return "", "", fmt.Errorf("error in AcceptStream: %w", err)
	}
	defer authStream.Close()

	authInfo, err := io.ReadAll(authStream)
	if err != nil {
		return "", "", fmt.Errorf("error in ReadAll: %w", err)
	}

	subdomainName, secret, found := strings.Cut(string(authInfo), ":")
	if !found {
		return "", "", fmt.Errorf("error in Cut '%v'", authInfo)
	}

	if !isValidSubdomainName(subdomainName) {
		return "", "", fmt.Errorf("invalid subdomain name: %s", subdomainName)
	}

	return subdomainName, secret, nil
}

func sendHTTPStatusCode(conn net.Conn, statusCode int) {
	response := http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}

	err := response.Write(conn)
	if err != nil {
		slog.Error("Error in sendHTTPStatusCode Write", slog.Any("error", err))
	}
}

func runJob(subdomainsStore *SubdomainsStore) {
	subdomainsStore.mu.Lock()
	defer subdomainsStore.mu.Unlock()

	for subdomainName, info := range subdomainsStore.subdomainNameToInfo {
		func() {
			info.mu.RLock()
			defer info.mu.RUnlock()

			if info.timeWhenNoOrigin.IsZero() {
				return
			}

			if time.Since(info.timeWhenNoOrigin) > 7*24*time.Hour {
				delete(subdomainsStore.subdomainNameToInfo, subdomainName)
			}
		}()
	}
}

func runJobs(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, subdomainsStore *SubdomainsStore) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Jobs is shutting down")

	for {
		runJob(subdomainsStore)

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func handleOriginConnection(ctx context.Context, originConnection *quic.Conn, subdomainsStore *SubdomainsStore) {
	defer originConnection.Close()

	slog.Info("Accepted origin connection", slog.String("connection", originConnection.String()))

	subdomainName, secret, err := doAuthentication(ctx, originConnection)
	if err != nil {
		slog.Error("Error in doAuthentication", slog.Any("error", err))
		return
	}

	err = subdomainAddConnectionIfSecret(subdomainsStore, subdomainName, secret, originConnection)
	if err != nil {
		slog.Error("Error in subdomainAddConnectionIfSecret", slog.Any("error", err))
		return
	}
	defer func() {
		err = subdomainRemoveConnection(subdomainsStore, subdomainName, originConnection)
		if err != nil {
			slog.Error("Error in subdomainRemoveConnection", slog.Any("error", err))
		}
	}()

	err = originConnection.Wait(ctx)
	if err != nil {
		slog.Error("Error in Wait", slog.Any("error", err))
	}
}

func runOrigins(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, subdomainsStore *SubdomainsStore, domain string, port string) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Origins is shutting down")

	serverTLS, err := certmagic.TLS([]string{domain})
	if err != nil {
		slog.Error("Error in TLS", slog.Any("error", err))
		return
	}
	serverTLS.NextProtos = []string{}
	serverTLS.MinVersion = tls.VersionTLS13

	serverEndpoint, err := quic.Listen("udp", fmt.Sprintf(":%s", port), &quic.Config{
		TLSConfig:       serverTLS,
		KeepAlivePeriod: 15 * time.Second,
		// QLogLogger: slog.Default(),
	})
	if err != nil {
		slog.Error("Error in Listen", slog.Any("error", err))
		return
	}
	defer serverEndpoint.Close(ctx)

	slog.Info("Listening for QUIC connections", slog.String("port", port))

	for {
		conn, err := serverEndpoint.Accept(ctx)
		if err != nil {
			slog.Error("Error in Accept", slog.Any("error", err))
			return
		}

		go handleOriginConnection(ctx, conn, subdomainsStore)
	}
}

func handleProxyConnection(ctx context.Context, clientConnection net.Conn, subdomainsStore *SubdomainsStore) {
	defer clientConnection.Close()

	slog.Info("Accepted proxy connection", slog.String("remoteAddr", clientConnection.RemoteAddr().String()))

	request, err := http.ReadRequest(bufio.NewReader(clientConnection))
	if err != nil {
		slog.Error("Error in ReadRequest", slog.Any("error", err))
		return
	}

	host := clientConnection.(*tls.Conn).ConnectionState().ServerName

	subdomainName, _, found := strings.Cut(host, ".")
	if !found {
		slog.Error("Error in Cut", slog.String("host", host))
		sendHTTPStatusCode(clientConnection, http.StatusBadRequest)
		return
	}

	remoteAddr := clientConnection.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		slog.Error("Error in SplitHostPort", slog.String("remoteAddr", remoteAddr), slog.Any("error", err))
		sendHTTPStatusCode(clientConnection, http.StatusInternalServerError)
		return
	}

	request.Header.Set("X-Forwarded-For", clientIP)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", host)

	originConnection := subdomainGetRandomConnection(subdomainsStore, subdomainName)
	if originConnection == nil {
		slog.Warn("No connection for subdomain", slog.String("subdomain", subdomainName))
		sendHTTPStatusCode(clientConnection, http.StatusServiceUnavailable)
		return
	}

	stream, err := originConnection.NewStream(ctx)
	if err != nil {
		slog.Error("Error in NewStream", slog.Any("error", err))
		sendHTTPStatusCode(clientConnection, http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()

	go func() {
		err = request.Write(stream)
		if err != nil {
			slog.Error("Error in Write", slog.Any("error", err))
			return
		}

		stream.Flush()
	}()

	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		slog.Error("Error in ReadResponse", slog.Any("error", err))
		sendHTTPStatusCode(clientConnection, http.StatusInternalServerError)
		return
	}

	err = response.Write(clientConnection)
	if err != nil {
		slog.Error("Error in Write", slog.Any("error", err))
		// Don't sendHTTPStatusCode() because we don't know what was written
		return
	}
}

func runProxy(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, subdomainsStore *SubdomainsStore, domain string) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Proxy is shutting down")

	tlsConfig, err := certmagic.TLS([]string{fmt.Sprintf("*.%s", domain)})
	if err != nil {
		slog.Error("Error in TLS", slog.Any("error", err))
		return
	}
	tlsConfig.NextProtos = []string{"http/1.1"} // TODO: support h2; keep in mind that ReadRequest only supports http/1.1

	listener, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		slog.Error("Error in Listen", slog.Any("error", err))
		return
	}
	defer listener.Close()

	// Close the listener when the context is done to unblock Accept
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	slog.Info("Listening for HTTP/1.1 over TLS on port 443")

	for {
		clientConnection, err := listener.Accept()
		if err != nil {
			slog.Error("Error in Accept", slog.Any("error", err))
			return
		}

		go handleProxyConnection(ctx, clientConnection, subdomainsStore)
	}
}

func main() {
	var PORT string
	var DOMAIN string
	var EMAIL string
	var CLOUDFLARE_API_TOKEN string

	flag.StringVar(&PORT, "port", "", "port")
	flag.StringVar(&DOMAIN, "domain", "", "domain name")
	flag.StringVar(&EMAIL, "email", "", "email address")
	flag.StringVar(&CLOUDFLARE_API_TOKEN, "cloudflare-api-token", "", "cloudflare API token with Zone.DNS Edit permission")
	flag.Parse()

	if PORT == "" || DOMAIN == "" || EMAIL == "" {
		flag.Usage()
		return
	}

	// TODO: support more providers: https://github.com/orgs/libdns/repositories
	var dnsProvider certmagic.DNSProvider
	if CLOUDFLARE_API_TOKEN != "" {
		dnsProvider = &cloudflare.Provider{
			APIToken: CLOUDFLARE_API_TOKEN,
		}
	} else {
		slog.Error("No DNS provider specified")
		return
	}

	certmagic.DefaultACME.Email = EMAIL
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: dnsProvider,
		},
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	shutdownWaitGroup := &sync.WaitGroup{}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	subdomainsStore := &SubdomainsStore{
		subdomainNameToInfo: make(map[string]*SubdomainInfo),
	}

	shutdownWaitGroup.Add(1)
	go runJobs(ctx, shutdownWaitGroup, cancelCtx, subdomainsStore)

	shutdownWaitGroup.Add(1)
	go runOrigins(ctx, shutdownWaitGroup, cancelCtx, subdomainsStore, DOMAIN, PORT)

	shutdownWaitGroup.Add(1)
	go runProxy(ctx, shutdownWaitGroup, cancelCtx, subdomainsStore, DOMAIN)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-ctx.Done():
	case <-quit:
		cancelCtx()
	}

	shutdownWaitGroup.Wait()
}
