package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/xcriminal/secret-hunter/pkg/patterns"
	"github.com/xcriminal/secret-hunter/pkg/scanner"
)

// Format defines output format type
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatTable Format = "table"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
	colorGray    = "\033[90m"
)

// Stats holds summary statistics
type Stats struct {
	DomainsScanned int
	URLsCrawled    int
	JSFilesScanned int
	SecretsFound   int
	StartTime      time.Time
	mu             sync.Mutex
}

func (s *Stats) AddURLCrawled()    { s.mu.Lock(); s.URLsCrawled++; s.mu.Unlock() }
func (s *Stats) AddJSScanned()     { s.mu.Lock(); s.JSFilesScanned++; s.mu.Unlock() }
func (s *Stats) AddSecret()        { s.mu.Lock(); s.SecretsFound++; s.mu.Unlock() }
func (s *Stats) SetDomains(n int)  { s.mu.Lock(); s.DomainsScanned = n; s.mu.Unlock() }

// Writer handles formatted output
type Writer struct {
	format   Format
	out      io.Writer
	noColor  bool
	mu       sync.Mutex
	findings []scanner.Finding
	seen     map[string]struct{}
}

// New creates a new output Writer
func New(format Format, out io.Writer, noColor bool) *Writer {
	if out == nil {
		out = os.Stdout
	}
	return &Writer{format: format, out: out, noColor: noColor, seen: make(map[string]struct{})}
}

// PrintBanner prints the tool banner
func (w *Writer) PrintBanner() {
	if w.format == FormatJSON {
		return
	}
	banner := `
  ___                   _   _   _             _
 / __| ___ __ _ _ ___ _| |_| | | |_  _ _ _  | |_ ___ _ _
 \__ \/ -_) _| '_/ -_)  _| |_| | ' \| | ' \ |  _/ -_) '_|
 |___/\___\__|_| \___|\__|\___/|_||_|\_,_|_|  \__\___|_|
                                    JS Secrets Hunter v1.0
`
	fmt.Fprintln(w.out, w.color(colorCyan+colorBold, banner))
}

// PrintStatus prints a status message to stderr
func PrintStatus(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
}

// PrintError prints an error message to stderr
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorRed+"[!] "+format+colorReset+"\n", args...)
}

// PrintInfo prints an info message to stderr
func PrintInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorGray+"[-] "+format+colorReset+"\n", args...)
}

// WriteFinding outputs a single finding
func (w *Writer) WriteFinding(f scanner.Finding) {
	w.mu.Lock()
	defer w.mu.Unlock()

	dedupKey := f.PatternName + "\x00" + f.RawMatch
	if _, dup := w.seen[dedupKey]; dup {
		return
	}
	w.seen[dedupKey] = struct{}{}

	w.findings = append(w.findings, f)

	if w.format == FormatJSON {
		return // buffered, written at end
	}

	sev := severityLabel(f.Severity, !w.noColor)
	sep := w.color(colorGray, strings.Repeat("─", 80))

	fmt.Fprintln(w.out, sep)
	fmt.Fprintf(w.out, " %s %s\n",
		sev,
		w.color(colorBold, f.PatternName),
	)
	fmt.Fprintf(w.out, " %s URL:     %s\n",
		w.color(colorGray, "│"),
		w.color(colorCyan, f.URL),
	)
	fmt.Fprintf(w.out, " %s Line:    %s\n",
		w.color(colorGray, "│"),
		w.color(colorYellow, fmt.Sprintf("%d", f.Line)),
	)
	fmt.Fprintf(w.out, " %s Match:   %s\n",
		w.color(colorGray, "│"),
		w.color(colorMagenta, f.Match),
	)
	fmt.Fprintf(w.out, " %s Context: %s\n",
		w.color(colorGray, "│"),
		w.color(colorGray, f.LineContent),
	)
}

// Flush writes buffered JSON or table output
func (w *Writer) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		w.writeJSON()
	case FormatTable:
		w.writeTable()
	}
}

// PrintSummary prints final statistics
func (w *Writer) PrintSummary(s *Stats) {
	if w.format == FormatJSON {
		return
	}
	elapsed := time.Since(s.StartTime).Round(time.Millisecond)
	fmt.Fprintln(w.out, w.color(colorGray, strings.Repeat("═", 80)))
	fmt.Fprintf(w.out, " %s Summary\n", w.color(colorBold, "►"))
	fmt.Fprintf(w.out, "   Domains:    %d\n", s.DomainsScanned)
	fmt.Fprintf(w.out, "   Crawled:    %d URLs\n", s.URLsCrawled)
	fmt.Fprintf(w.out, "   JS Files:   %d scanned\n", s.JSFilesScanned)
	fmt.Fprintf(w.out, "   Secrets:    %s\n", w.color(colorBold+colorRed, fmt.Sprintf("%d found", s.SecretsFound)))
	fmt.Fprintf(w.out, "   Time:       %s\n", elapsed)
	fmt.Fprintln(w.out, w.color(colorGray, strings.Repeat("═", 80)))
}

func (w *Writer) writeJSON() {
	type jsonFinding struct {
		URL         string `json:"url"`
		PatternName string `json:"pattern"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Match       string `json:"match"`
		Line        int    `json:"line"`
		LineContent string `json:"line_content"`
	}

	out := make([]jsonFinding, 0, len(w.findings))
	for _, f := range w.findings {
		out = append(out, jsonFinding{
			URL:         f.URL,
			PatternName: f.PatternName,
			Severity:    string(f.Severity),
			Description: f.Description,
			Match:       f.Match,
			Line:        f.Line,
			LineContent: f.LineContent,
		})
	}

	enc := json.NewEncoder(w.out)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck
}

func (w *Writer) writeTable() {
	tw := tabwriter.NewWriter(w.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tPATTERN\tURL\tLINE\tMATCH")
	fmt.Fprintln(tw, "--------\t-------\t---\t----\t-----")
	for _, f := range w.findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			f.Severity, f.PatternName, f.URL, f.Line, f.Match)
	}
	tw.Flush()
}

func (w *Writer) color(code, s string) string {
	if w.noColor {
		return s
	}
	return code + s + colorReset
}

func severityLabel(sev patterns.Severity, colored bool) string {
	labels := map[patterns.Severity]string{
		patterns.SeverityCritical: "CRITICAL",
		patterns.SeverityHigh:     "HIGH    ",
		patterns.SeverityMedium:   "MEDIUM  ",
		patterns.SeverityLow:      "LOW     ",
		patterns.SeverityInfo:     "INFO    ",
	}
	colors := map[patterns.Severity]string{
		patterns.SeverityCritical: colorRed + colorBold,
		patterns.SeverityHigh:     colorRed,
		patterns.SeverityMedium:   colorYellow,
		patterns.SeverityLow:      colorGreen,
		patterns.SeverityInfo:     colorCyan,
	}

	label := "[" + labels[sev] + "]"
	if colored {
		return colors[sev] + label + colorReset
	}
	return label
}
