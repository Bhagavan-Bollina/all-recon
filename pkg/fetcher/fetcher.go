package fetcher

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds HTTP client settings
type Config struct {
	Timeout    time.Duration
	Headers    map[string]string
	ProxyURL   string
	SkipTLS    bool
	MaxBodyMB  int
	UserAgent  string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Timeout:   15 * time.Second,
		MaxBodyMB: 10,
		UserAgent: "Mozilla/5.0 (compatible; SecretHunter/1.0; +https://github.com/xcriminal/secret-hunter)",
	}
}

// Client wraps an HTTP client for fetching JS content
type Client struct {
	http *http.Client
	cfg  Config
}

// New creates a new fetcher Client
func New(cfg Config) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipTLS}, //nolint:gosec
	}

	return &Client{
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cfg: cfg,
	}
}

// Fetch downloads a URL or reads a local file and returns its content as a string
func (c *Client) Fetch(url string) (string, error) {
	// Support local file paths
	if strings.HasPrefix(url, "file://") {
		data, err := os.ReadFile(strings.TrimPrefix(url, "file://"))
		return string(data), err
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// Treat as local file path
		data, err := os.ReadFile(url)
		return string(data), err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	maxBytes := int64(c.cfg.MaxBodyMB) * 1024 * 1024
	if maxBytes == 0 {
		maxBytes = 10 * 1024 * 1024
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// IsJSURL returns true if the URL/path likely points to a JavaScript file
func IsJSURL(url string) bool {
	lower := strings.ToLower(url)
	// Local file paths
	if !strings.HasPrefix(lower, "http") && (strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".jsx") || strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx") || strings.HasSuffix(lower, ".mjs")) {
		return true
	}
	// Check extension
	if strings.Contains(lower, ".js") {
		// Exclude map files and CSS-only references
		if strings.HasSuffix(lower, ".js") ||
			strings.HasSuffix(lower, ".js?") ||
			strings.Contains(lower, ".js?") ||
			strings.Contains(lower, ".js#") {
			return true
		}
		// Handle .jsx, .mjs, .cjs, .ts (compiled)
		for _, ext := range []string{".jsx", ".mjs", ".cjs", ".ts", ".tsx"} {
			if strings.Contains(lower, ext) {
				return true
			}
		}
	}
	return false
}
