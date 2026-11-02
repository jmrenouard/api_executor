package plugins

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCryptoHashUtilityPlugin_VerifyHMAC_MatchingAndNonMatching(t *testing.T) {
	ctx := context.Background()
	p := &CryptoHashUtilityPlugin{}

	input := "api-executor-security-audit-2026"
	key := "my-secret-hmac-key"

	// Compute genuine reference HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(input))
	genuineHMAC := hex.EncodeToString(mac.Sum(nil))

	// 1. Verify with matching expected HMAC -> matched: true
	resMatching, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input":         input,
		"key":           key,
		"expected_hmac": genuineHMAC,
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("expected verify_hmac to succeed, got err: %v", err)
	}
	if resMatching.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", resMatching.Status)
	}
	dataMatching, ok := resMatching.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resMatching.Data)
	}
	if matched, ok := dataMatching["matched"].(bool); !ok || !matched {
		t.Errorf("expected matched=true for genuine HMAC, got %+v", dataMatching)
	}
	if dataMatching["computed_hmac"] != genuineHMAC {
		t.Errorf("expected computed_hmac=%s, got %v", genuineHMAC, dataMatching["computed_hmac"])
	}

	// 2. Verify with case-insensitive uppercase expected HMAC -> matched: true
	resUpper, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input":         input,
		"key":           key,
		"expected_hmac": strings.ToUpper(genuineHMAC),
	}, 5*time.Second)
	if err != nil || resUpper.Status != "ok" {
		t.Fatalf("expected uppercase verify_hmac to succeed, got %v (%+v)", err, resUpper)
	}
	dataUpper, ok := resUpper.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resUpper.Data)
	}
	if matched, ok := dataUpper["matched"].(bool); !ok || !matched {
		t.Errorf("expected matched=true for uppercase HMAC, got %+v", dataUpper)
	}

	// 3. Verify with mismatched expected HMAC (single flipped byte) -> matched: false
	tamperedHMAC := genuineHMAC[:len(genuineHMAC)-2] + "ff"
	resMismatched, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input":         input,
		"key":           key,
		"expected_hmac": tamperedHMAC,
	}, 5*time.Second)
	if err != nil || resMismatched.Status != "ok" {
		t.Fatalf("expected verify_hmac to succeed with matched=false, got %v (%+v)", err, resMismatched)
	}
	dataMismatched, ok := resMismatched.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resMismatched.Data)
	}
	if matched, ok := dataMismatched["matched"].(bool); !ok || matched {
		t.Errorf("expected matched=false for tampered HMAC, got %+v", dataMismatched)
	}

	// 4. Verify with different length expected HMAC -> matched: false
	resWrongLen, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input":         input,
		"key":           key,
		"expected_hmac": "deadbeef",
	}, 5*time.Second)
	if err != nil || resWrongLen.Status != "ok" {
		t.Fatalf("expected verify_hmac with short HMAC to succeed with matched=false, got %v (%+v)", err, resWrongLen)
	}
	dataWrongLen, ok := resWrongLen.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resWrongLen.Data)
	}
	if matched, ok := dataWrongLen["matched"].(bool); !ok || matched {
		t.Errorf("expected matched=false for wrong length HMAC, got %+v", dataWrongLen)
	}

	// 5. Verify without expected HMAC -> matched: true, computed_hmac returned
	resNoExpected, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input": input,
		"key":   key,
	}, 5*time.Second)
	if err != nil || resNoExpected.Status != "ok" {
		t.Fatalf("expected verify_hmac without expected to succeed, got %v", err)
	}
	dataNoExpected, ok := resNoExpected.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resNoExpected.Data)
	}
	if dataNoExpected["computed_hmac"] != genuineHMAC {
		t.Errorf("expected computed_hmac=%s, got %v", genuineHMAC, dataNoExpected["computed_hmac"])
	}

	// 6. Verify missing key -> error
	resMissingKey, err := p.Execute(ctx, "verify_hmac", map[string]any{
		"input": input,
	}, 5*time.Second)
	if err == nil || resMissingKey.Status != "error" {
		t.Errorf("expected error for missing key, got err=%v res=%+v", err, resMissingKey)
	}
}

func TestCryptoHashUtilityPlugin_HashStringAndDetect(t *testing.T) {
	ctx := context.Background()
	p := &CryptoHashUtilityPlugin{}

	// Test hash_string with algorithm=all
	resHash, err := p.Execute(ctx, "hash_string", map[string]any{
		"input":     "hello-world",
		"algorithm": "all",
	}, 5*time.Second)
	if err != nil || resHash.Status != "ok" {
		t.Fatalf("hash_string failed: %v", err)
	}
	dataHash, ok := resHash.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any data, got %T", resHash.Data)
	}
	for _, algo := range []string{"md5", "sha1", "sha256", "sha384", "sha512"} {
		if _, ok := dataHash[algo]; !ok {
			t.Errorf("expected %s in hash_string output", algo)
		}
	}

	// Test detect_algorithm
	hashes := map[string]string{
		"5d41402abc4b2a76b9719d911017c592":                                 "MD5 (128-bit)",
		"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d":                         "SHA-1 (160-bit)",
		"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae": "SHA-256 (256-bit)",
	}
	for h, expectedAlgo := range hashes {
		resDetect, err := p.Execute(ctx, "detect_algorithm", map[string]any{"hash": h}, 5*time.Second)
		if err != nil || resDetect.Status != "ok" {
			t.Errorf("detect_algorithm failed for %s: %v", h, err)
		}
		dataDetect, ok := resDetect.Data.(map[string]any)
		if !ok {
			t.Fatalf("expected map[string]any data, got %T", resDetect.Data)
		}
		if dataDetect["algorithm"] != expectedAlgo {
			t.Errorf("expected %s for %s, got %v", expectedAlgo, h, dataDetect["algorithm"])
		}
	}

	// Unknown action
	resUnknown, err := p.Execute(ctx, "non_existent_action", nil, 5*time.Second)
	if err != ErrActionNotFound || resUnknown.Status != "error" {
		t.Errorf("expected ErrActionNotFound, got %v (%+v)", err, resUnknown)
	}
}
