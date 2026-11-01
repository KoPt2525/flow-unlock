package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	cfg := defaultConfig()
	parseFlags(cfg)

	exportPath := flag.String("export-ca", "", "write the CA certificate (PEM) to this path and exit")
	genCADir := flag.String("gen-ca", "", "generate a CA certificate/key into this directory and exit")
	showStatus := flag.Bool("status", false, "print the current status and exit")

	flag.Parse()
	cfg.applyUCI()

	logger := log.New(os.Stderr, "[flow-local] ", log.LstdFlags)

	if *genCADir != "" {
		if err := generateCAFiles(*genCADir); err != nil {
			logger.Fatalf("generate CA: %v", err)
		}
		fmt.Printf("CA generated in %s\n", *genCADir)
		return
	}

	if *exportPath != "" {
		ca, _ := loadCA(cfg.CACert, cfg.CAKey)
		if err := exportCA(ca, *exportPath); err != nil {
			logger.Fatalf("export CA: %v", err)
		}
		fmt.Printf("CA certificate written to %s\n", *exportPath)
		return
	}

	if *showStatus {
		printStatus(cfg)
		return
	}

	srv := newServer(cfg, logger)
	proxyHandler := srv.newProxyHandler()

	proxyAddr := net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.ProxyPort))
	proxyServer := &http.Server{Addr: proxyAddr, Handler: proxyHandler}
	go func() {
		logger.Printf("explicit proxy listening on %s", proxyAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("explicit proxy: %v", err)
		}
	}()

	if cfg.Transparent {
		httpAddr := net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.TransparentHTTPPort))
		httpServer := &http.Server{Addr: httpAddr, Handler: proxyHandler}
		go func() {
			logger.Printf("transparent HTTP listening on %s", httpAddr)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("transparent HTTP: %v", err)
			}
		}()

		httpsAddr := net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.TransparentHTTPSPort))
		httpsLn, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			logger.Fatalf("transparent HTTPS listen: %v", err)
		}
		go func() {
			logger.Printf("transparent HTTPS listening on %s", httpsAddr)
			srv.serveTransparentHTTPS(httpsLn)
		}()
	}

	logger.Printf("enabled=%v handle_redirect=%v transparent=%v", cfg.Enabled, cfg.HandleRedirect, cfg.Transparent)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			reloaded := defaultConfig()
			reloaded.applyUCI()
			srv.applyRuntime(reloaded)
			logger.Printf("reloaded: enabled=%v handle_redirect=%v cooldown=%ds",
				reloaded.Enabled, reloaded.HandleRedirect, reloaded.CooldownSeconds)
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Printf("shutting down")
			return
		}
	}
}

func printStatus(cfg *Config) {
	enabled := cfg.Enabled
	if uciAvailable() {
		if v, ok := uciGet("enabled"); ok {
			enabled = v == "1" || v == "true"
		}
	}
	fmt.Printf("enabled: %v\n", enabled)
	fmt.Printf("handle_redirect: %v\n", cfg.HandleRedirect)

	data, err := os.ReadFile(cfg.StatusFile)
	if err != nil {
		fmt.Println("last run: (none)")
		return
	}
	fmt.Println("last run:")
	fmt.Println(strings.TrimSpace(string(data)))
}

// generateCAFiles writes a fresh CA certificate/key into dir, refusing to
// overwrite an existing CA (so installed client certificates stay valid).
func generateCAFiles(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", keyPath)
	}

	certPEM, keyPEM, err := generateCA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}
