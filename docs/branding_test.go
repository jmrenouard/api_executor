package docs

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
)

func TestSVGAssetsAreValidXMLAndREADMEIncludesBranding(t *testing.T) {
	svgFiles := []string{
		"assets/logo.svg",
		"assets/header-banner.svg",
	}

	for _, path := range svgFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		if !strings.Contains(string(raw), "<svg") {
			t.Fatalf("expected %s to contain <svg root element", path)
		}

		decoder := xml.NewDecoder(bytes.NewReader(raw))
		for {
			_, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("invalid XML in %s: %v", path, err)
			}
		}
	}

	readmeBytes, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("failed to read ../README.md: %v", err)
	}
	readme := string(readmeBytes)

	requiredMarkers := []string{
		"docs/assets/header-banner.svg",
		"docs/assets/logo.svg",
		"HTTPS / TLS 1.3",
		"action_calls_total",
		"action_calls_ok_total",
		"action_calls_error_total",
		"action_calls_failure_total",
		"Ubuntu",
		"RedHat",
		"Service Accounts",
		"db-exposure",
		"/api/v1/mcp",
		"docs/ACTION_LOGBOOK.md",
		"docs/RCA_REGISTER.md",
	}

	for _, marker := range requiredMarkers {
		if !strings.Contains(readme, marker) {
			t.Errorf("expected README.md to contain %q", marker)
		}
	}

	if SwaggerInfo.Title == "" {
		t.Errorf("expected SwaggerInfo.Title to be initialized")
	}
}
