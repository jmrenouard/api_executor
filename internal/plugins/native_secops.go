package plugins

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// FileIntegrityCheckerPlugin computes cryptographic file checksums, verifies manifests, and audits directory trees.
type FileIntegrityCheckerPlugin struct{}

func (p *FileIntegrityCheckerPlugin) ID() string          { return "file-integrity-checker" }
func (p *FileIntegrityCheckerPlugin) Name() string        { return "Cryptographic File Hash & Integrity Scanner" }
func (p *FileIntegrityCheckerPlugin) Version() string     { return "1.0.0" }
func (p *FileIntegrityCheckerPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *FileIntegrityCheckerPlugin) Type() string        { return "native" }
func (p *FileIntegrityCheckerPlugin) Category() string    { return "SecOps" }
func (p *FileIntegrityCheckerPlugin) Description() string {
	return "Computes SHA-256/SHA-512/MD5 digests, verifies checksum manifests, and generates deterministic tree hashes."
}

func (p *FileIntegrityCheckerPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "file_checksums",
			Description: "Compute multi-algorithm cryptographic hashes for a file",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Target file path"},
			},
		},
		{
			Name:        "verify_manifest",
			Description: "Verify a file or artifact against an expected hash",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Target file path"},
				{Name: "expected_hash", Type: "string", Required: true, Description: "Expected hash digest"},
				{Name: "algorithm", Type: "string", Required: false, Default: "sha256", Description: "Algorithm: sha256, sha512, md5"},
			},
		},
		{
			Name:        "dir_hash_audit",
			Description: "Compute deterministic Merkle-style root hash of directory files",
			Timeout:     "15s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Target directory path"},
			},
		},
	}
}

func (p *FileIntegrityCheckerPlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "file_checksums":
		targetPath := getStringParam(params, "path", "")
		if targetPath == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'path' is required",
			}, fmt.Errorf("parameter 'path' is required")
		}

		f, err := os.Open(targetPath)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}
		defer f.Close()

		h256 := sha256.New()
		h512 := sha512.New()
		hMD5 := md5.New()
		mw := io.MultiWriter(h256, h512, hMD5)

		written, err := io.Copy(mw, f)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}

		data := map[string]any{
			"path":       targetPath,
			"size_bytes": written,
			"sha256":     hex.EncodeToString(h256.Sum(nil)),
			"sha512":     hex.EncodeToString(h512.Sum(nil)),
			"md5":        hex.EncodeToString(hMD5.Sum(nil)),
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "verify_manifest":
		targetPath := getStringParam(params, "path", "")
		expected := strings.ToLower(getStringParam(params, "expected_hash", ""))
		algo := strings.ToLower(getStringParam(params, "algorithm", "sha256"))
		if targetPath == "" || expected == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameters 'path' and 'expected_hash' are required",
			}, fmt.Errorf("parameters 'path' and 'expected_hash' are required")
		}

		f, err := os.Open(targetPath)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}
		defer f.Close()

		var actual string
		switch algo {
		case "md5":
			h := md5.New()
			_, _ = io.Copy(h, f)
			actual = hex.EncodeToString(h.Sum(nil))
		case "sha512":
			h := sha512.New()
			_, _ = io.Copy(h, f)
			actual = hex.EncodeToString(h.Sum(nil))
		default:
			h := sha256.New()
			_, _ = io.Copy(h, f)
			actual = hex.EncodeToString(h.Sum(nil))
		}

		matched := (actual == expected)
		data := map[string]any{
			"path":          targetPath,
			"algorithm":     algo,
			"expected_hash": expected,
			"actual_hash":   actual,
			"matched":       matched,
		}

		status := "ok"
		if !matched {
			status = "failure"
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: status, Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "dir_hash_audit":
		targetPath := getStringParam(params, "path", "")
		if targetPath == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'path' is required",
			}, fmt.Errorf("parameter 'path' is required")
		}

		var fileHashes []string
		count := 0
		err := filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil || d.IsDir() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			h := sha256.New()
			_, _ = io.Copy(h, f)
			rel, _ := filepath.Rel(targetPath, path)
			fileHashes = append(fileHashes, fmt.Sprintf("%s:%s", rel, hex.EncodeToString(h.Sum(nil))))
			count++
			return nil
		})

		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(), Error: err.Error(),
			}, err
		}

		sort.Strings(fileHashes)
		rootHasher := sha256.New()
		for _, fh := range fileHashes {
			rootHasher.Write([]byte(fh + "\n"))
		}
		rootHash := hex.EncodeToString(rootHasher.Sum(nil))

		data := map[string]any{
			"path":       targetPath,
			"file_count": count,
			"root_hash":  rootHash,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}

// PasswordPolicyAuditPlugin audits credential complexity, Shannon entropy, and NIST compliance.
type PasswordPolicyAuditPlugin struct{}

func (p *PasswordPolicyAuditPlugin) ID() string          { return "password-policy-audit" }
func (p *PasswordPolicyAuditPlugin) Name() string        { return "Credential Complexity & Policy Evaluator" }
func (p *PasswordPolicyAuditPlugin) Version() string     { return "1.0.0" }
func (p *PasswordPolicyAuditPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *PasswordPolicyAuditPlugin) Type() string        { return "native" }
func (p *PasswordPolicyAuditPlugin) Category() string    { return "SecOps" }
func (p *PasswordPolicyAuditPlugin) Description() string {
	return "Evaluates password candidate entropy, NIST SP 800-63B guidelines, and character pool distribution."
}

func (p *PasswordPolicyAuditPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "evaluate_entropy",
			Description: "Calculate Shannon information entropy (bits) of input candidate string",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "password", Type: "string", Required: true, Description: "Candidate string to evaluate"},
			},
		},
		{
			Name:        "nist_compliance",
			Description: "Audit compliance with NIST SP 800-63B password guidance",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "password", Type: "string", Required: true, Description: "Candidate string to audit"},
			},
		},
		{
			Name:        "character_dist",
			Description: "Analyze character pool distributions (uppercase, lowercase, digits, symbols)",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "password", Type: "string", Required: true, Description: "Candidate string to analyze"},
			},
		},
	}
}

var commonPasswords = map[string]struct{}{
	"password": {}, "123456": {}, "12345678": {}, "admin": {}, "root": {}, "qwerty": {},
	"letmein": {}, "welcome": {}, "changeme": {}, "iloveyou": {},
}

func (p *PasswordPolicyAuditPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	candidate := getStringParam(params, "password", "")

	if candidate == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'password' is required",
		}, fmt.Errorf("parameter 'password' is required")
	}

	length := len(candidate)
	var upper, lower, digits, symbols int
	freq := make(map[rune]int)

	for _, r := range candidate {
		freq[r]++
		switch {
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		case unicode.IsDigit(r):
			digits++
		default:
			symbols++
		}
	}

	// Shannon entropy calculation
	var entropy float64
	for _, count := range freq {
		prob := float64(count) / float64(length)
		entropy -= prob * math.Log2(prob)
	}
	totalBits := entropy * float64(length)

	switch normalized {
	case "evaluate_entropy":
		strength := "weak"
		if totalBits >= 60 {
			strength = "very_strong"
		} else if totalBits >= 40 {
			strength = "strong"
		} else if totalBits >= 25 {
			strength = "moderate"
		}

		data := map[string]any{
			"length":                 length,
			"entropy_per_char_bits": fmt.Sprintf("%.2f", entropy),
			"total_entropy_bits":    fmt.Sprintf("%.2f", totalBits),
			"strength_rating":       strength,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "nist_compliance":
		_, isCommon := commonPasswords[strings.ToLower(candidate)]
		meetsLength := length >= 8
		noRepetition := true
		if strings.Repeat(string(candidate[0]), length) == candidate {
			noRepetition = false
		}
		compliant := meetsLength && !isCommon && noRepetition

		data := map[string]any{
			"length":           length,
			"min_length_8":     meetsLength,
			"not_common":       !isCommon,
			"not_all_repeated": noRepetition,
			"nist_compliant":   compliant,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "character_dist":
		data := map[string]any{
			"length":          length,
			"uppercase_count": upper,
			"lowercase_count": lower,
			"digit_count":     digits,
			"symbol_count":    symbols,
			"unique_chars":    len(freq),
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}
