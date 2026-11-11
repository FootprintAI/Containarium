package runhook

import (
	"fmt"
	"regexp"
)

// Redacted replaces a redacted part of an argument.
const Redacted = "[REDACTED]"

// MaxRedactPatterns bounds the operator's additions.
const MaxRedactPatterns = 64

type redactRule struct {
	re   *regexp.Regexp
	repl string
}

// defaultRedactions are always applied. Each keeps what identifies the shape
// of the argument (a flag name, a URL scheme) and replaces the secret part.
var defaultRedactions = []redactRule{
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), Redacted},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), Redacted},
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), Redacted},
	{regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`), Redacted},
	{regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`), Redacted},
	{regexp.MustCompile(`A[KS]IA[0-9A-Z]{16}`), Redacted},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), Redacted},
	{regexp.MustCompile(`(?i)(bearer|basic|token)\s+\S+`), "${1} " + Redacted},
	{regexp.MustCompile(`(://)[^/\s:@]+:[^/\s@]+@`), "${1}" + Redacted + "@"},
	{regexp.MustCompile(`(?i)^(--?(?:[a-z0-9-]*[-_])?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|auth|credentials?)[=:])(.+)$`), "${1}" + Redacted},
}

// secretFlag is a flag whose value is the next argument.
var secretFlag = regexp.MustCompile(`(?i)^--?(?:[a-z0-9-]*[-_])?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|auth|credentials?)$`)

// Redactor replaces secret-looking parts of arguments.
type Redactor struct {
	rules []redactRule
}

// NewRedactor builds a Redactor from the default list plus the operator's
// additional RE2 patterns; any match of an addition is replaced by Redacted.
func NewRedactor(extra []string) (*Redactor, error) {
	if len(extra) > MaxRedactPatterns {
		return nil, fmt.Errorf("%d redaction patterns, at most %d are allowed", len(extra), MaxRedactPatterns)
	}
	r := &Redactor{rules: append([]redactRule(nil), defaultRedactions...)}
	for _, p := range extra {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redaction pattern %q: %w", p, err)
		}
		r.rules = append(r.rules, redactRule{re, Redacted})
	}
	return r, nil
}

// Argv returns a redacted copy of argv.
func (r *Redactor) Argv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if i > 0 && secretFlag.MatchString(argv[i-1]) {
			out[i] = Redacted
			continue
		}
		for _, rule := range r.rules {
			a = rule.re.ReplaceAllString(a, rule.repl)
		}
		out[i] = a
	}
	return out
}
