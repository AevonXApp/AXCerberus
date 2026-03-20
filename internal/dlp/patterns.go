// Package dlp provides Data Leak Prevention by scanning response bodies.
package dlp

import "regexp"

// PatternType identifies the category of sensitive data detected.
type PatternType string

const (
	PatternCreditCard  PatternType = "credit_card"
	PatternAPIKey      PatternType = "api_key"
	PatternStackTrace  PatternType = "stack_trace"
	PatternDBError     PatternType = "database_error"
	PatternInternalIP  PatternType = "internal_ip"
)

// Match represents a detected sensitive data occurrence.
type Match struct {
	Type    PatternType `json:"type"`
	Value   string      `json:"value"` // redacted preview
	Offset  int         `json:"offset"`
}

// DetectionPattern pairs a compiled regex with its category.
type DetectionPattern struct {
	Type    PatternType
	Pattern *regexp.Regexp
}

// CreditCardPatterns detects card numbers (Visa, MC, Amex, Discover).
var CreditCardPatterns = []DetectionPattern{
	{PatternCreditCard, regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)},        // Visa
	{PatternCreditCard, regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)},                 // MasterCard
	{PatternCreditCard, regexp.MustCompile(`\b3[47][0-9]{13}\b`)},                  // Amex
	{PatternCreditCard, regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`)},     // Discover
}

// APIKeyPatterns detects known API key formats.
var APIKeyPatterns = []DetectionPattern{
	{PatternAPIKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},                        // AWS Access Key
	{PatternAPIKey, regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},                     // GitHub PAT
	{PatternAPIKey, regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},                     // GitHub OAuth
	{PatternAPIKey, regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)},                // Stripe Secret
	{PatternAPIKey, regexp.MustCompile(`rk_live_[A-Za-z0-9]{24,}`)},                // Stripe Restricted
	{PatternAPIKey, regexp.MustCompile(`sk-[A-Za-z0-9]{48}`)},                      // OpenAI
	{PatternAPIKey, regexp.MustCompile(`xox[bprs]-[A-Za-z0-9\-]{10,}`)},            // Slack Token
	{PatternAPIKey, regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`)}, // SendGrid
}

// StackTracePatterns detects error stack traces from various languages.
var StackTracePatterns = []DetectionPattern{
	{PatternStackTrace, regexp.MustCompile(`(?i)Fatal error:.*in\s+/[^\s]+\s+on line\s+\d+`)},           // PHP
	{PatternStackTrace, regexp.MustCompile(`Traceback \(most recent call last\)`)},                       // Python
	{PatternStackTrace, regexp.MustCompile(`(?m)^\s+at\s+[\w.$]+\([\w.]+:\d+\)`)},                      // Java
	{PatternStackTrace, regexp.MustCompile(`(?m)^Error.*\n\s+at\s+`)},                                  // Node.js
	{PatternStackTrace, regexp.MustCompile(`(?i)panic:\s+runtime error`)},                               // Go
	{PatternStackTrace, regexp.MustCompile(`(?i)System\.(\w+Exception|NullReferenceException)`)},        // .NET
}

// DBErrorPatterns detects database error messages.
var DBErrorPatterns = []DetectionPattern{
	{PatternDBError, regexp.MustCompile(`(?i)you have an error in your sql syntax`)},
	{PatternDBError, regexp.MustCompile(`(?i)ERROR:\s+(?:syntax error|relation .+ does not exist)`)},    // PostgreSQL
	{PatternDBError, regexp.MustCompile(`(?i)ORA-\d{5}`)},                                              // Oracle
	{PatternDBError, regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`)},                // MSSQL
	{PatternDBError, regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`)},                                        // PDO
}

// InternalIPPattern detects private/internal IPs in response bodies.
var InternalIPPattern = DetectionPattern{
	PatternInternalIP,
	regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
}

// LuhnValid validates a credit card number using the Luhn algorithm.
func LuhnValid(number string) bool {
	var sum int
	nDigits := len(number)
	parity := nDigits % 2

	for i := 0; i < nDigits; i++ {
		digit := int(number[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}
