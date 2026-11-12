package docs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if !strings.Contains(readme, "redhat-rpm-qa") || strings.Contains(readme, "redhat-rpm-packages") {
		t.Errorf("expected README.md to reference real preset name redhat-rpm-qa instead of redhat-rpm-packages")
	}

	rootDockerfile, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatalf("failed to read ../Dockerfile: %v", err)
	}
	rootDF := string(rootDockerfile)
	for _, marker := range []string{"/app/certs", "chown -R appuser:appgroup /app", "COPY --from=builder /app/plugins ./plugins"} {
		if !strings.Contains(rootDF, marker) {
			t.Errorf("expected root Dockerfile to contain %q", marker)
		}
	}

	if SwaggerInfo.Title == "" {
		t.Errorf("expected SwaggerInfo.Title to be initialized")
	}
}

func TestDockerHygieneAndIgnoreRules(t *testing.T) {
	// 1. Verify root .dockerignore exists and excludes required patterns
	dockerignoreBytes, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatalf("failed to read ../.dockerignore: %v", err)
	}
	dockerignore := string(dockerignoreBytes)
	requiredIgnores := []string{
		".git",
		".worktrees",
		".agents",
		"bin/",
		"tmp/",
		"*.db",
		"*.sqlite*",
		"*.log",
		".vscode/",
		".idea/",
	}
	for _, pattern := range requiredIgnores {
		if !strings.Contains(dockerignore, pattern) {
			t.Errorf("expected .dockerignore to contain %q", pattern)
		}
	}

	// 2. Verify root Dockerfile layer caching optimization
	rootDockerfile, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatalf("failed to read ../Dockerfile: %v", err)
	}
	rootDF := string(rootDockerfile)
	modDownloadIdx := strings.Index(rootDF, "RUN go mod download")
	copyAllIdx := strings.Index(rootDF, "COPY . .")
	if modDownloadIdx == -1 {
		t.Errorf("expected root Dockerfile to contain 'RUN go mod download'")
	}
	if copyAllIdx == -1 {
		t.Errorf("expected root Dockerfile to contain 'COPY . .'")
	}
	if modDownloadIdx > copyAllIdx {
		t.Errorf("expected 'RUN go mod download' to appear before 'COPY . .'")
	}

	// 3. Verify docker/Dockerfile.redhat installs curl for container healthcheck
	redhatDockerfile, err := os.ReadFile("../docker/Dockerfile.redhat")
	if err != nil {
		t.Fatalf("failed to read ../docker/Dockerfile.redhat: %v", err)
	}
	redhatDF := string(redhatDockerfile)
	for _, marker := range []string{"ca-certificates", "curl-minimal", "procps-ng", "iproute"} {
		if !strings.Contains(redhatDF, marker) {
			t.Errorf("expected docker/Dockerfile.redhat to install %q", marker)
		}
	}
}

func TestAgentRulesConsolidationAndDeduplication(t *testing.T) {
	// Verify that redundant workflow rule files (git-workflow.md, github-workflow.md) have been removed
	// and that atomic-workflow.md serves as canonical.
	rulesDir := "../.agents/rules"
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", rulesDir, err)
	}

	expectedFiles := map[string]bool{
		"atomic-workflow.md":    true,
		"english-only.md":       true,
		"project-governance.md": true,
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !expectedFiles[entry.Name()] {
			t.Errorf("unexpected file in .agents/rules: %s (expected only deduplicated rules)", entry.Name())
		}
	}

	for expected := range expectedFiles {
		path := filepath.Join(rulesDir, expected)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected canonical rule file %s to exist: %v", expected, err)
		}
	}

	atomicWorkflowBytes, err := os.ReadFile(filepath.Join(rulesDir, "atomic-workflow.md"))
	if err != nil {
		t.Fatalf("failed to read atomic-workflow.md: %v", err)
	}
	content := string(atomicWorkflowBytes)
	for _, marker := range []string{
		"One Correction / Feature = One Issue = One Branch = One PR = One Merge",
		"Complete 8-Step GitHub Lifecycle per Atomic Item",
		"Open an Atomic GitHub Issue",
		"Create a Dedicated Atomic Branch",
		"TDD Implementation & Verification",
		"Update Governance Registers",
		"Atomic Commit & Push",
		"Open Atomic Pull Request",
		"Merge Pull Request",
		"Close Issue with Summary Comment",
	} {
		if !strings.Contains(content, marker) {
			t.Errorf("expected atomic-workflow.md to contain marker %q", marker)
		}
	}
}

func TestReleaseWorkflowChecksumDeliverablesAndREADMEHygiene(t *testing.T) {
	// 1. Verify .github/workflows/release.yml standardizes checksum deliverables
	workflowBytes, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatalf("failed to read ../.github/workflows/release.yml: %v", err)
	}
	workflow := string(workflowBytes)

	requiredWorkflowMarkers := []string{
		`sha256sum "$file" > "${file}.sha256"`,
		"sha256sum api_executor-*.tar.gz api_executor-*.zip > SHA256SUMS.txt",
		"sha256sum -c SHA256SUMS.txt",
		`sha256sum -c "$ckfile"`,
		"dist/api_executor-*.sha256",
		"dist/SHA256SUMS.txt",
		"body_path: dist/RELEASE_NOTES_VERIFICATION.md",
		"append_body: true",
	}

	for _, marker := range requiredWorkflowMarkers {
		if !strings.Contains(workflow, marker) {
			t.Errorf("expected .github/workflows/release.yml to contain %q", marker)
		}
	}

	// 2. Verify README.md hygiene (no hardcoded version-specific checksum matrices or hashes)
	readmeBytes, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("failed to read ../README.md: %v", err)
	}
	readme := string(readmeBytes)

	bannedReadmeMarkers := []string{
		"#### Platform Artifact Matrix (v2.1.0)",
		"#### Official SHA-256 Checksums Manifest (v2.1.0)",
		"fe3151e0d38c18b128d97d39c2b07bc73fbce2ef13c66b486f0040ece11f0bff",
		"3e3499dea256f04f65d04bbe18e328314c07d30aa3249c662b52cc9d8f3610c2",
		"0416391a74ab35f8e738386803f1425881dced9e286a5d2c7864074fd41007af",
		"44472b648619187585727ddb97e8a140ae12eab700ffa3262cc513f15c2f9af3",
		"e136b9f36f82a78ddf83b704de5b0c6802363bb8fd643f4db53cbc230f054e11",
		"e50d18e9fa956e477b6e4776e72ba8014425704d987babd59456e653d3b0439d",
		"7a683f37173220cd1f8da7fdfe007e36e269fe417673d9e860658e9095a496ef",
	}

	for _, marker := range bannedReadmeMarkers {
		if strings.Contains(readme, marker) {
			t.Errorf("README.md must not contain hardcoded version checksum marker %q", marker)
		}
	}

	// Verify README.md contains templated verification guidelines
	requiredReadmeMarkers := []string{
		"SHA256SUMS.txt",
		"${ARCHIVE}.sha256",
		"$ARCHIVE.sha256",
		"github.com/jmrenouard/api_executor/releases",
	}
	for _, marker := range requiredReadmeMarkers {
		if !strings.Contains(readme, marker) {
			t.Errorf("README.md should contain generic verification reference %q", marker)
		}
	}

	// 3. Cryptographic simulation of checksum generation and validation
	tmpDir := t.TempDir()
	sampleArchives := map[string][]byte{
		"api_executor-v2.1.0-linux-amd64.tar.gz":  []byte("linux-amd64 binary payload"),
		"api_executor-v2.1.0-windows-amd64.zip":   []byte("windows-amd64 binary payload"),
	}

	var manifestLines []string
	for filename, content := range sampleArchives {
		filePath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("failed to write mock archive %s: %v", filename, err)
		}
		hash := sha256.Sum256(content)
		hashHex := hex.EncodeToString(hash[:])
		line := fmt.Sprintf("%s  %s", hashHex, filename)
		manifestLines = append(manifestLines, line)

		// Create individual .sha256 file
		shaPath := filePath + ".sha256"
		if err := os.WriteFile(shaPath, []byte(line+"\n"), 0644); err != nil {
			t.Fatalf("failed to write individual checksum file %s: %v", shaPath, err)
		}
	}

	manifestPath := filepath.Join(tmpDir, "SHA256SUMS.txt")
	manifestContent := strings.Join(manifestLines, "\n") + "\n"
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write SHA256SUMS.txt: %v", err)
	}

	// Validate manifest parser format: 64-hex hash followed by two spaces and filename
	for _, line := range manifestLines {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			t.Errorf("invalid manifest line format: %q", line)
		}
		expectedContent, ok := sampleArchives[parts[1]]
		if !ok {
			t.Errorf("unexpected archive in manifest: %s", parts[1])
			continue
		}
		actualHash := sha256.Sum256(expectedContent)
		if parts[0] != hex.EncodeToString(actualHash[:]) {
			t.Errorf("hash mismatch for %s: expected %s, got %s", parts[1], hex.EncodeToString(actualHash[:]), parts[0])
		}
	}
}




