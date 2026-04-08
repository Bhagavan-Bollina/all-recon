package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/xcriminal/secret-hunter/pkg/crawler"
	"github.com/xcriminal/secret-hunter/pkg/fetcher"
	"github.com/xcriminal/secret-hunter/pkg/output"
	"github.com/xcriminal/secret-hunter/pkg/scanner"
)

var (
	// Input flags
	flagDomains    []string
	flagURLs       []string
	flagInputFile  string

	// Crawler flags
	flagCrawler    string
	flagDepth      int
	flagConcurrency int
	flagHeadless   bool
	flagScope      []string

	// HTTP flags
	flagHeaders    []string
	flagProxy      string
	flagSkipTLS    bool
	flagTimeout    int

	// Output flags
	flagFormat   string
	flagOutput   string
	flagNoColor  bool
	flagSilent   bool
	flagVerbose  bool

	// Scan flags
	flagJSOnly      bool
	flagSeverity    string
	flagShowSecrets bool

	// JS-only mode: pass a list of JS URLs directly to scan without crawling
	flagJSURLs     []string
	flagJSListFile string
)

var rootCmd = &cobra.Command{
	Use:   "secret-hunter",
	Short: "JS Secret Hunter — find hardcoded secrets in JavaScript files",
	Long: `secret-hunter crawls domains/URLs, extracts all JavaScript files,
and scans them for hardcoded secrets using 60+ regex patterns.

Examples:
  # Crawl a domain and hunt for secrets
  secret-hunter -d example.com

  # Multiple domains from file
  secret-hunter -l domains.txt

  # Use katana as crawler
  secret-hunter -d example.com --crawler katana

  # Scan specific JS URLs directly (no crawling)
  secret-hunter --js https://example.com/app.js

  # JSON output to file
  secret-hunter -d example.com -o results.json -f json

  # Pipe from subfinder + httpx
  echo "example.com" | subfinder -silent | httpx -silent | secret-hunter --stdin`,

	RunE: runScan,
}

// Execute is the CLI entry point
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Input
	rootCmd.Flags().StringSliceVarP(&flagDomains, "domain", "d", nil, "Target domain(s) to crawl (comma-separated or repeated)")
	rootCmd.Flags().StringSliceVarP(&flagURLs, "url", "u", nil, "Target URL(s) to crawl")
	rootCmd.Flags().StringVarP(&flagInputFile, "list", "l", "", "File containing targets (one per line, domains or URLs)")
	rootCmd.Flags().StringSliceVar(&flagJSURLs, "js", nil, "Scan specific JS URL(s) directly without crawling")
	rootCmd.Flags().StringVar(&flagJSListFile, "js-list", "", "File containing JS URLs to scan directly (one per line, no crawling)")
	rootCmd.Flags().Bool("stdin", false, "Read targets from stdin (one per line)")

	// Crawler
	rootCmd.Flags().StringVar(&flagCrawler, "crawler", "builtin", "Crawler backend: builtin, katana, hakrawler")
	rootCmd.Flags().IntVar(&flagDepth, "depth", 3, "Crawl depth")
	rootCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 15, "Concurrent crawl threads")
	rootCmd.Flags().BoolVar(&flagHeadless, "headless", false, "Use headless browser (katana only)")
	rootCmd.Flags().StringSliceVar(&flagScope, "scope", nil, "Additional in-scope domains")

	// HTTP
	rootCmd.Flags().StringSliceVarP(&flagHeaders, "header", "H", nil, "Custom headers (format: 'Name: Value')")
	rootCmd.Flags().StringVar(&flagProxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().BoolVar(&flagSkipTLS, "skip-tls", false, "Skip TLS certificate verification")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 15, "HTTP request timeout in seconds")

	// Output
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "Output format: text, json, table")
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file")
	rootCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	rootCmd.Flags().BoolVarP(&flagSilent, "silent", "s", false, "Suppress banner and status messages")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show each crawled URL and HTTP status")

	// Scan
	rootCmd.Flags().StringVar(&flagSeverity, "severity", "", "Severity filter: single threshold (HIGH) or comma-separated exact list (HIGH,CRITICAL)")
	rootCmd.Flags().BoolVar(&flagShowSecrets, "show-secrets", false, "Print full unredacted secret values (use with care)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// ── Collect targets ──────────────────────────────────────────────────────────
	targets := collectTargets(cmd)

	// Load --js-list file into flagJSURLs
	if flagJSListFile != "" {
		f, err := os.Open(flagJSListFile)
		if err != nil {
			return fmt.Errorf("cannot open --js-list file: %w", err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				flagJSURLs = append(flagJSURLs, line)
			}
		}
		f.Close()
	}

	if len(targets) == 0 && len(flagJSURLs) == 0 {
		return fmt.Errorf("no targets provided — use -d, -u, -l, --js, --js-list, or --stdin")
	}

	// ── Setup output writer ───────────────────────────────────────────────────────
	outFmt := output.Format(flagFormat)
	var outFile *os.File
	var outWriter *output.Writer

	if flagOutput != "" {
		var err error
		outFile, err = os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer outFile.Close()
		outWriter = output.New(outFmt, outFile, true)
	} else {
		outWriter = output.New(outFmt, os.Stdout, flagNoColor)
	}

	if !flagSilent {
		outWriter.PrintBanner()
	}

	// ── Build configs ─────────────────────────────────────────────────────────────
	headers := parseHeaders(flagHeaders)

	crawlCfg := crawler.Config{
		Mode:        crawler.Mode(flagCrawler),
		Depth:       flagDepth,
		Concurrency: flagConcurrency,
		Timeout:     time.Duration(flagTimeout) * time.Second,
		Headers:     headers,
		ProxyURL:    flagProxy,
		Scope:       flagScope,
		SkipTLS:     flagSkipTLS,
		Headless:    flagHeadless,
		Verbose:     flagVerbose,
	}

	fetchCfg := fetcher.Config{
		Timeout:   time.Duration(flagTimeout) * time.Second,
		Headers:   headers,
		ProxyURL:  flagProxy,
		SkipTLS:   flagSkipTLS,
		MaxBodyMB: 20,
	}

	stats := &output.Stats{StartTime: time.Now()}
	stats.SetDomains(len(targets))

	// ── Context with signal handling ──────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		output.PrintError("Interrupted — flushing results...")
		cancel()
	}()

	httpClient := fetcher.New(fetchCfg)
	scanOpts := scanner.Options{ShowSecrets: flagShowSecrets}

	// ── Direct JS URL mode (no crawl) ─────────────────────────────────────────────
	if len(flagJSURLs) > 0 {
		total := len(flagJSURLs)
		if !flagSilent {
			output.PrintStatus("Scanning %d JS URL(s) with %d workers...", total, flagConcurrency)
		}

		jobs := make(chan string, flagConcurrency*2)
		var wg sync.WaitGroup
		var done int64

		// Launch fixed worker pool
		for i := 0; i < flagConcurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for jsURL := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}
					scanJSURL(ctx, jsURL, httpClient, outWriter, stats, flagSeverity, flagSilent, scanOpts)
					n := atomic.AddInt64(&done, 1)
					if !flagSilent && flagVerbose {
						fmt.Fprintf(os.Stderr, "\r[*] Progress: %d/%d", n, total)
					}
				}
			}()
		}

		// Feed jobs
		for _, jsURL := range flagJSURLs {
			select {
			case <-ctx.Done():
				break
			case jobs <- jsURL:
			}
		}
		close(jobs)
		wg.Wait()

		if !flagSilent && flagVerbose {
			fmt.Fprintln(os.Stderr) // newline after progress line
		}
	}

	// ── Crawl + scan mode ─────────────────────────────────────────────────────────
	if len(targets) > 0 {
		if !flagSilent {
			output.PrintStatus("Starting crawl with %s backend (depth=%d, concurrency=%d)...",
				flagCrawler, flagDepth, flagConcurrency)
		}

		urlCh, err := crawler.Crawl(ctx, targets, crawlCfg)
		if err != nil {
			return fmt.Errorf("crawler error: %w", err)
		}

		// Track JS URLs already scanned
		scanned := &sync.Map{}
		var wg sync.WaitGroup
		sem := make(chan struct{}, flagConcurrency)

		for result := range urlCh {
			stats.AddURLCrawled()

			if !result.IsJS {
				continue
			}

			if _, loaded := scanned.LoadOrStore(result.URL, true); loaded {
				continue
			}

			wg.Add(1)
			r := result
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				scanJSURL(ctx, r.URL, httpClient, outWriter, stats, flagSeverity, flagSilent, scanOpts)
			}()
		}

		wg.Wait()
	}

	// ── Finalize output ───────────────────────────────────────────────────────────
	outWriter.Flush()

	if !flagSilent {
		outWriter.PrintSummary(stats)
	}

	return nil
}

func scanJSURL(ctx context.Context, jsURL string, client *fetcher.Client, w *output.Writer, stats *output.Stats, minSev string, silent bool, scanOpts scanner.Options) {
	if flagVerbose {
		output.PrintInfo("Scanning JS: %s", jsURL)
	}

	content, err := client.Fetch(jsURL)
	if err != nil {
		if flagVerbose {
			output.PrintError("Fetch failed [%s]: %v", jsURL, err)
		}
		return
	}

	stats.AddJSScanned()

	findings := scanner.ScanContent(jsURL, content, scanOpts)
	for _, f := range findings {
		if !meetsSeverity(string(f.Severity), minSev) {
			continue
		}
		stats.AddSecret()
		w.WriteFinding(f)
	}
}

// collectTargets gathers all target URLs/domains from flags, files, and stdin
func collectTargets(cmd *cobra.Command) []string {
	seen := make(map[string]bool)
	var targets []string

	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			return
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	for _, d := range flagDomains {
		add(d)
	}
	for _, u := range flagURLs {
		add(u)
	}

	if flagInputFile != "" {
		f, err := os.Open(flagInputFile)
		if err != nil {
			output.PrintError("Cannot open input file: %v", err)
		} else {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				add(sc.Text())
			}
			f.Close()
		}
	}

	useStdin, _ := cmd.Flags().GetBool("stdin")
	if useStdin {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			add(sc.Text())
		}
	}

	return targets
}

func parseHeaders(raw []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func meetsSeverity(sev, filter string) bool {
	if filter == "" {
		return true
	}
	order := map[string]int{
		"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
	}
	sevUpper := strings.ToUpper(sev)
	// Comma-separated list: --severity HIGH,CRITICAL → match any in the list
	parts := strings.Split(strings.ToUpper(filter), ",")
	if len(parts) > 1 {
		for _, p := range parts {
			if strings.TrimSpace(p) == sevUpper {
				return true
			}
		}
		return false
	}
	// Single value: treat as minimum threshold (HIGH = HIGH + CRITICAL)
	return order[sevUpper] >= order[parts[0]]
}
