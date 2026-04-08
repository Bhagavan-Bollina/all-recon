package crawler

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/xcriminal/secret-hunter/pkg/fetcher"
)

// Mode determines which crawler backend to use
type Mode string

const (
	ModeBuiltin   Mode = "builtin"
	ModeKatana    Mode = "katana"
	ModeHakrawler Mode = "hakrawler"
)

// Real Chrome 124 UA — passes most bot detection that blocks random/old UAs
const chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Config holds crawler settings
type Config struct {
	Mode        Mode
	Depth       int
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	ProxyURL    string
	Scope       []string
	SkipTLS     bool
	Headless    bool
	UserAgent   string
	Verbose     bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Mode:        ModeBuiltin,
		Depth:       3,
		Concurrency: 10,
		Timeout:     30 * time.Second,
		UserAgent:   chromeUA,
	}
}

// Result holds a discovered URL and its context
type Result struct {
	URL    string
	Source string
	IsJS   bool
}

// Crawl starts crawling targets and returns discovered URLs via channel
func Crawl(ctx context.Context, targets []string, cfg Config) (<-chan Result, error) {
	out := make(chan Result, 4096)

	if cfg.UserAgent == "" {
		cfg.UserAgent = chromeUA
	}

	switch cfg.Mode {
	case ModeKatana:
		go func() { defer close(out); runKatana(ctx, targets, cfg, out) }()
	case ModeHakrawler:
		go func() { defer close(out); runHakrawler(ctx, targets, cfg, out) }()
	default:
		go func() { defer close(out); runBuiltin(ctx, targets, cfg, out) }()
	}

	return out, nil
}

// regexScriptSrc extracts JS URLs from raw HTML body via regex (fallback for bot-challenged pages)
var regexScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.(?:js|mjs|jsx|ts|tsx)[^"']*)["']`)

// regexPreloadJS matches <link rel="preload/prefetch" as="script" href="...">
var regexPreloadJS = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"']+\.js[^"']*)["']`)

func runBuiltin(ctx context.Context, targets []string, cfg Config, out chan<- Result) {
	seen := &sync.Map{}

	// Build in-scope domain set: always include www. variant
	domainSet := make(map[string]bool)
	for _, t := range targets {
		if d := extractDomain(t); d != "" {
			domainSet[d] = true
			if strings.HasPrefix(d, "www.") {
				domainSet[strings.TrimPrefix(d, "www.")] = true
			} else {
				domainSet["www."+d] = true
			}
		}
	}
	for _, s := range cfg.Scope {
		domainSet[s] = true
	}

	inScope := func(rawURL string) bool {
		d := extractDomain(rawURL)
		return d != "" && domainSet[d]
	}

	emit := func(rawURL, source string) {
		if rawURL == "" || !strings.HasPrefix(rawURL, "http") {
			return
		}
		if _, loaded := seen.LoadOrStore(rawURL, true); loaded {
			return
		}
		select {
		case out <- Result{URL: rawURL, Source: source, IsJS: fetcher.IsJSURL(rawURL)}:
		case <-ctx.Done():
		}
	}

	// No AllowedDomains — we handle scope filtering ourselves so Colly
	// doesn't interfere with redirect chains (gap.com → www.gap.com).
	c := colly.NewCollector(
		colly.MaxDepth(cfg.Depth),
		colly.Async(true),
	)

	if cfg.SkipTLS {
		c.WithTransport(insecureTransport())
	}

	// Use real Chrome UA — bot protection blocks random/old UA strings
	c.UserAgent = cfg.UserAgent

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		r.Headers.Set("Accept-Language", "en-US,en;q=0.5")
		for k, v := range cfg.Headers {
			r.Headers.Set(k, v)
		}
		if cfg.Verbose {
			fmt.Fprintf(logWriter, "[CRAWL] %s\n", r.URL.String())
		}
	})

	c.Limit(&colly.LimitRule{ //nolint:errcheck
		DomainGlob:  "*",
		Parallelism: cfg.Concurrency,
		Delay:       100 * time.Millisecond,
	})

	// HTML handlers — primary extraction path
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		emit(src, e.Request.URL.String())
	})

	c.OnHTML("script:not([src])", func(e *colly.HTMLElement) {
		for _, jsURL := range extractURLsFromJS(e.Text, e.Request.URL.String()) {
			emit(jsURL, e.Request.URL.String())
		}
	})

	c.OnHTML("link[href]", func(e *colly.HTMLElement) {
		href := e.Request.AbsoluteURL(e.Attr("href"))
		if fetcher.IsJSURL(href) {
			emit(href, e.Request.URL.String())
		}
	})

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if !inScope(link) {
			return
		}
		emit(link, e.Request.URL.String())
		c.Visit(link) //nolint:errcheck
	})

	// Raw body extraction — fallback for bot-challenged/minified pages
	c.OnResponse(func(r *colly.Response) {
		final := r.Request.URL.String()
		emit(final, "visited")

		if cfg.Verbose {
			fmt.Fprintf(logWriter, "[RESP]  %d %s\n", r.StatusCode, final)
		}

		// Expand scope to cover redirect-landed domains
		if d := extractDomain(final); d != "" && !domainSet[d] {
			domainSet[d] = true
		}

		// Use the RESPONSE URL (after redirects) as base for relative path resolution
		// r.Request.URL may still point to the pre-redirect URL in Colly,
		// so parse it from the actual response headers if possible.
		base := r.Request.URL
		if loc := r.Headers.Get("Location"); loc == "" {
			// Not a redirect response — final URL is reliable
			if u, err := url.Parse(final); err == nil {
				base = u
			}
		}
		body := string(r.Body)

		for _, m := range regexScriptSrc.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				resolved := resolveRef(m[1], base)
				emit(resolved, final)
			}
		}
		for _, m := range regexPreloadJS.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				resolved := resolveRef(m[1], base)
				if fetcher.IsJSURL(resolved) {
					emit(resolved, final)
				}
			}
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		if cfg.Verbose {
			fmt.Fprintf(logWriter, "[ERR]   %s → %v\n", r.Request.URL.String(), err)
		}
	})

	for _, t := range targets {
		normalized := normalizeURL(t)
		emit(normalized, "input")
		c.Visit(normalized) //nolint:errcheck

		// Also explicitly visit www. variant to bypass gap.com → www.gap.com redirect issues
		d := extractDomain(normalized)
		if d != "" && !strings.HasPrefix(d, "www.") {
			u, err := url.Parse(normalized)
			if err == nil {
				u.Host = "www." + d
				www := u.String()
				emit(www, "input")
				c.Visit(www) //nolint:errcheck
			}
		}
	}

	done := make(chan struct{})
	go func() { c.Wait(); close(done) }()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// runKatana pipes targets into katana and reads output
func runKatana(ctx context.Context, targets []string, cfg Config, out chan<- Result) {
	args := []string{
		"-silent",
		"-d", fmt.Sprintf("%d", cfg.Depth),
		"-c", fmt.Sprintf("%d", cfg.Concurrency),
		"-jc",      // parse JS for additional endpoints
		"-kf", "all",
	}

	if cfg.Headless {
		args = append(args, "-headless")
	}

	for k, v := range cfg.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	if len(targets) == 1 {
		args = append(args, "-u", targets[0])
	} else {
		args = append(args, "-list", "-")
	}

	cmd := exec.CommandContext(ctx, "katana", args...)
	if len(targets) > 1 {
		cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	seen := &sync.Map{}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, loaded := seen.LoadOrStore(line, true); loaded {
			continue
		}
		select {
		case out <- Result{URL: line, Source: "katana", IsJS: fetcher.IsJSURL(line)}:
		case <-ctx.Done():
			cmd.Cancel() //nolint:errcheck
			return
		}
	}
	cmd.Wait() //nolint:errcheck
}

// runHakrawler pipes targets into hakrawler and reads output
func runHakrawler(ctx context.Context, targets []string, cfg Config, out chan<- Result) {
	args := []string{"-d", fmt.Sprintf("%d", cfg.Depth)}

	for k, v := range cfg.Headers {
		args = append(args, "-h", fmt.Sprintf("%s: %s", k, v))
	}

	cmd := exec.CommandContext(ctx, "hakrawler", args...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	seen := &sync.Map{}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, loaded := seen.LoadOrStore(line, true); loaded {
			continue
		}
		select {
		case out <- Result{URL: line, Source: "hakrawler", IsJS: fetcher.IsJSURL(line)}:
		case <-ctx.Done():
			return
		}
	}
	cmd.Wait() //nolint:errcheck
}

// resolveRef resolves a possibly-relative reference against a base URL
func resolveRef(ref string, base *url.URL) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func extractDomain(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		return "https://" + raw
	}
	return raw
}

func extractURLsFromJS(text, base string) []string {
	var found []string
	baseURL, err := url.Parse(base)
	if err != nil {
		return found
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, ".js") {
			continue
		}
		for _, part := range strings.Fields(line) {
			part = strings.Trim(part, `'"`+"`"+`,;()[]{}`)
			if strings.HasSuffix(part, ".js") || strings.Contains(part, ".js?") || strings.Contains(part, ".js#") {
				resolved := resolveRef(part, baseURL)
				if strings.HasPrefix(resolved, "http") {
					found = append(found, resolved)
				}
			}
		}
	}
	return found
}
