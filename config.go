package main

import (
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Config is the runtime configuration. Static fields (ports, CA paths) are read
// once at startup; the toggled fields (Enabled, HandleRedirect, CooldownSeconds)
// are copied into atomics by server.applyRuntime and can be reloaded on SIGHUP.
type Config struct {
	ListenAddr          string
	ProxyPort           int
	TransparentHTTPPort int
	TransparentHTTPSPort int
	Transparent         bool
	HandleRedirect      bool
	Enabled             bool
	CooldownSeconds     int
	CACert              string
	CAKey               string
	StatusFile          string
	Verbose             bool
}

func defaultConfig() *Config {
	return &Config{
		ListenAddr:           "0.0.0.0",
		ProxyPort:            8080,
		TransparentHTTPPort:  3128,
		TransparentHTTPSPort: 8443,
		Transparent:          false,
		HandleRedirect:       true,
		Enabled:              true,
		CooldownSeconds:      15,
		CACert:               "/etc/flow-local/ca.crt",
		CAKey:                "/etc/flow-local/ca.key",
		StatusFile:           "/tmp/flow-local/status.json",
		Verbose:              false,
	}
}

func parseFlags(cfg *Config) {
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address for the explicit proxy")
	flag.IntVar(&cfg.ProxyPort, "proxy-port", cfg.ProxyPort, "explicit proxy port (CONNECT + HTTP)")
	flag.IntVar(&cfg.TransparentHTTPPort, "transparent-http-port", cfg.TransparentHTTPPort, "transparent HTTP redirect port")
	flag.IntVar(&cfg.TransparentHTTPSPort, "transparent-https-port", cfg.TransparentHTTPSPort, "transparent HTTPS redirect port")
	flag.BoolVar(&cfg.Transparent, "transparent", cfg.Transparent, "enable transparent interception listeners")
	flag.BoolVar(&cfg.HandleRedirect, "handle-redirect", cfg.HandleRedirect, "MITM flow.google.com and handle /unsupported-country redirects")
	flag.BoolVar(&cfg.Enabled, "enabled", cfg.Enabled, "enable automatic processing")
	flag.IntVar(&cfg.CooldownSeconds, "cooldown", cfg.CooldownSeconds, "redirect cooldown in seconds")
	flag.StringVar(&cfg.CACert, "ca-cert", cfg.CACert, "path to CA certificate (PEM)")
	flag.StringVar(&cfg.CAKey, "ca-key", cfg.CAKey, "path to CA private key (PEM)")
	flag.StringVar(&cfg.StatusFile, "status-file", cfg.StatusFile, "path to the JSON status file")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "verbose logging")
}

func uciAvailable() bool {
	if _, err := exec.LookPath("uci"); err != nil {
		return false
	}
	if _, err := os.Stat("/etc/config/flow-local"); err != nil {
		return false
	}
	return true
}

func uciGet(option string) (string, bool) {
	out, err := exec.Command("uci", "-q", "get", "flow-local.flow."+option).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// applyUCI overrides the config from /etc/config/flow-local when running on
// OpenWrt. Values present in UCI win over flag defaults.
func (c *Config) applyUCI() {
	if !uciAvailable() {
		return
	}
	if v, ok := uciGet("enabled"); ok {
		c.Enabled = v == "1" || v == "true"
	}
	if v, ok := uciGet("transparent"); ok {
		c.Transparent = v == "1" || v == "true"
	}
	if v, ok := uciGet("handle_redirect"); ok {
		c.HandleRedirect = v == "1" || v == "true"
	}
	if v, ok := uciGet("listen_addr"); ok && v != "" {
		c.ListenAddr = v
	}
	if v, ok := uciGet("proxy_port"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.ProxyPort = n
		}
	}
	if v, ok := uciGet("transparent_http_port"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.TransparentHTTPPort = n
		}
	}
	if v, ok := uciGet("transparent_https_port"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.TransparentHTTPSPort = n
		}
	}
	if v, ok := uciGet("cooldown_seconds"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.CooldownSeconds = n
		}
	}
	if v, ok := uciGet("ca_cert"); ok && v != "" {
		c.CACert = v
	}
	if v, ok := uciGet("ca_key"); ok && v != "" {
		c.CAKey = v
	}
	if v, ok := uciGet("status_file"); ok && v != "" {
		c.StatusFile = v
	}
	if v, ok := uciGet("verbose"); ok {
		c.Verbose = v == "1" || v == "true"
	}
}
