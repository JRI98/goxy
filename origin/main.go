package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	var PORT string

	flag.StringVar(&PORT, "port", "", "port")
	flag.Parse()

	if PORT == "" {
		flag.Usage()
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("client_ip", r.Header.Get("X-Forwarded-For")))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	slog.Info("Listening for HTTP/1.1 requests", slog.String("port", PORT))

	err := http.ListenAndServe(fmt.Sprintf(":%s", PORT), nil)
	if err != nil {
		slog.Error("Error in ListenAndServe", slog.Any("error", err))
	}
}
