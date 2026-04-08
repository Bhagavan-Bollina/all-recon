package scanner

import (
	"math"
	"strings"

	"github.com/xcriminal/secret-hunter/pkg/patterns"
)

// Finding represents a detected secret
type Finding struct {
	URL         string
	PatternName string
	Severity    patterns.Severity
	Description string
	Match       string
	RawMatch    string // full unredacted value
	Line        int
	LineContent string
}

// Options controls scanner behavior
type Options struct {
	ShowSecrets bool // if true, include raw unredacted match in output
}

// ScanContent scans JavaScript content for secrets and returns findings
func ScanContent(sourceURL, content string, opts Options) []Finding {
	var findings []Finding

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, p := range patterns.Patterns {
			matches := p.Regex.FindAllString(line, -1)
			for _, match := range matches {
				// Context regex filter
				if p.ContextRegex != nil && !p.ContextRegex.MatchString(line) {
					continue
				}

				// FP reduction: entropy check for generic patterns
				if p.EntropyCheck {
					if shannonEntropy(match) < p.MinEntropy {
						continue
					}
				}

				// FP reduction: skip if the match is obviously a placeholder/example
				if isFakePlaceholder(match) {
					continue
				}

				raw := match
				display := match
				if !opts.ShowSecrets {
					display = redact(match)
				}

				findings = append(findings, Finding{
					URL:         sourceURL,
					PatternName: p.Name,
					Severity:    p.Severity,
					Description: p.Description,
					Match:       display,
					RawMatch:    raw,
					Line:        lineNum + 1,
					LineContent: truncate(strings.TrimSpace(line), 200),
				})
			}
		}
	}

	return findings
}

// shannonEntropy calculates the Shannon entropy of a string
// High entropy (>3.5) suggests a real random secret, not a placeholder
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	l := float64(len(s))
	for _, count := range freq {
		p := count / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isFakePlaceholder returns true for obvious example/placeholder strings
// that commonly appear in docs, comments, and template code in JS bundles
var placeholders = []string{
	"EXAMPLE", "example", "YOUR_", "your_", "INSERT_", "insert_",
	"REPLACE_", "replace_", "PLACEHOLDER", "placeholder",
	"XXXXXXXXXXXX", "xxxxxxxxxxxx", "000000000000",
	"aaaaaaaaaaaa", "AAAAAAAAAAAA",
	"1234567890", "abcdefghij",
	"test_key", "TEST_KEY", "demo_key", "DEMO_KEY",
	"<YOUR", "<your", "MY_KEY", "my_key",
}

func isFakePlaceholder(s string) bool {
	for _, p := range placeholders {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// redact keeps first 6 and last 4 chars visible, masks the middle
func redact(s string) string {
	const show = 6
	if len(s) <= show+4 {
		return s
	}
	return s[:show] + strings.Repeat("*", len(s)-show-4) + s[len(s)-4:]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
