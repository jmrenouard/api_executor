package core

import (
	"os"
	"runtime"
	"strings"
)

// OSPresetCatalog holds a named collection of predefined OS administration commands.
type OSPresetCatalog struct {
	OSFamily    string              `json:"os_family" yaml:"os_family"`
	DisplayName string              `json:"display_name" yaml:"display_name"`
	DockerImage string              `json:"docker_image" yaml:"docker_image"`
	Description string              `json:"description" yaml:"description"`
	Commands    []CommandDefinition `json:"commands" yaml:"commands"`
}

// UbuntuPresetCommands returns predefined administration tasks for Ubuntu / Debian systems (testable in Docker ubuntu:24.04).
func UbuntuPresetCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:        "ubuntu-os-release",
			Description: "Inspect Ubuntu / Debian distribution metadata (/etc/os-release)",
			OSFamily:    "ubuntu",
			Category:    "system",
			Command:     "cat",
			Args:        []string{"/etc/os-release"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-kernel-uname",
			Description: "Display kernel release, architecture, and hostname on Ubuntu",
			OSFamily:    "ubuntu",
			Category:    "system",
			Command:     "uname",
			Args:        []string{"-a"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-dpkg-packages",
			Description: "List installed Debian/Ubuntu packages with version and architecture via dpkg-query",
			OSFamily:    "ubuntu",
			Category:    "packages",
			Command:     "dpkg-query",
			Args:        []string{"-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"},
			Timeout:     "20s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-apt-simulated-upgrade",
			Description: "Perform a dry-run simulation of pending APT package upgrades without modifying the system",
			OSFamily:    "ubuntu",
			Category:    "packages",
			Command:     "apt-get",
			Args:        []string{"-s", "upgrade"},
			Timeout:     "30s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-apt-sources",
			Description: "List configured APT package repositories and sources",
			OSFamily:    "ubuntu",
			Category:    "packages",
			Command:     "apt-cache",
			Args:        []string{"policy"},
			Timeout:     "15s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-disk-space",
			Description: "Report Ubuntu filesystem disk space usage in human-readable format",
			OSFamily:    "ubuntu",
			Category:    "storage",
			Command:     "df",
			Args:        []string{"-h"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-memory-stats",
			Description: "Display Ubuntu physical and swap memory utilization (/proc/meminfo)",
			OSFamily:    "ubuntu",
			Category:    "system",
			Command:     "cat",
			Args:        []string{"/proc/meminfo"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-process-snapshot",
			Description: "Capture a non-interactive snapshot of running processes on Ubuntu",
			OSFamily:    "ubuntu",
			Category:    "processes",
			Command:     "ps",
			Args:        []string{"-ef"},
			Timeout:     "15s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-network-sockets",
			Description: "List listening TCP/UDP network sockets using ss",
			OSFamily:    "ubuntu",
			Category:    "network",
			Command:     "ss",
			Args:        []string{"-tuln"},
			Timeout:     "15s",
			Preset:      true,
		},
		{
			Name:        "ubuntu-passwd-accounts",
			Description: "Audit local system user accounts in /etc/passwd",
			OSFamily:    "ubuntu",
			Category:    "security",
			Command:     "cat",
			Args:        []string{"/etc/passwd"},
			Timeout:     "10s",
			Preset:      true,
		},
	}
}

// RedHatPresetCommands returns predefined administration tasks for RedHat / RHEL / Rocky / AlmaLinux / UBI systems (testable in Docker redhat/ubi9 or rockylinux:9).
func RedHatPresetCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:        "redhat-os-release",
			Description: "Inspect RedHat / RHEL / UBI release metadata (/etc/os-release)",
			OSFamily:    "redhat",
			Category:    "system",
			Command:     "cat",
			Args:        []string{"/etc/os-release"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "redhat-system-release",
			Description: "Read RedHat / Enterprise Linux /etc/redhat-release banner",
			OSFamily:    "redhat",
			Category:    "system",
			Command:     "cat",
			Args:        []string{"/etc/redhat-release"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "redhat-rpm-qa",
			Description: "Query all installed RPM packages with version, release, and architecture",
			OSFamily:    "redhat",
			Category:    "packages",
			Command:     "rpm",
			Args:        []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"},
			Timeout:     "25s",
			Preset:      true,
		},
		{
			Name:        "redhat-rpm-verify-crypto",
			Description: "Verify integrity of installed core crypto/system RPM files",
			OSFamily:    "redhat",
			Category:    "security",
			Command:     "rpm",
			Args:        []string{"-V", "setup"},
			Timeout:     "20s",
			Preset:      true,
		},
		{
			Name:        "redhat-dnf-repolist",
			Description: "List enabled DNF / YUM software repositories on RedHat",
			OSFamily:    "redhat",
			Category:    "packages",
			Command:     "dnf",
			Args:        []string{"repolist", "--quiet"},
			Timeout:     "30s",
			Preset:      true,
		},
		{
			Name:        "redhat-disk-space",
			Description: "Report RedHat filesystem disk space usage in human-readable format",
			OSFamily:    "redhat",
			Category:    "storage",
			Command:     "df",
			Args:        []string{"-h"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "redhat-memory-stats",
			Description: "Display RedHat physical and swap memory utilization (/proc/meminfo)",
			OSFamily:    "redhat",
			Category:    "system",
			Command:     "cat",
			Args:        []string{"/proc/meminfo"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "redhat-process-snapshot",
			Description: "Capture a non-interactive snapshot of running processes on RedHat",
			OSFamily:    "redhat",
			Category:    "processes",
			Command:     "ps",
			Args:        []string{"-ef"},
			Timeout:     "15s",
			Preset:      true,
		},
		{
			Name:        "redhat-kernel-uname",
			Description: "Display RedHat kernel release, build timestamp, and CPU architecture",
			OSFamily:    "redhat",
			Category:    "system",
			Command:     "uname",
			Args:        []string{"-a"},
			Timeout:     "10s",
			Preset:      true,
		},
		{
			Name:        "redhat-passwd-accounts",
			Description: "Audit local system user accounts in /etc/passwd on RedHat",
			OSFamily:    "redhat",
			Category:    "security",
			Command:     "cat",
			Args:        []string{"/etc/passwd"},
			Timeout:     "10s",
			Preset:      true,
		},
	}
}

// AllOSPresetCatalogs returns the structured catalog of predefined tasks for Ubuntu and RedHat.
func AllOSPresetCatalogs() []OSPresetCatalog {
	return []OSPresetCatalog{
		{
			OSFamily:    "ubuntu",
			DisplayName: "Ubuntu / Debian Linux (22.04 / 24.04 LTS)",
			DockerImage: "ubuntu:24.04",
			Description: "Predefined administration, package auditing (APT/DPKG), storage, process, network, and security tasks for Ubuntu and Debian containers/hosts.",
			Commands:    UbuntuPresetCommands(),
		},
		{
			OSFamily:    "redhat",
			DisplayName: "RedHat Enterprise Linux / Rocky / UBI 9",
			DockerImage: "redhat/ubi9:latest",
			Description: "Predefined administration, RPM package verification, DNF repository inspection, storage, process, and security tasks for RHEL, Rocky Linux, AlmaLinux, and RedHat UBI containers/hosts.",
			Commands:    RedHatPresetCommands(),
		},
	}
}

// GetOSPresetCommands returns predefined commands matching the requested OS families ("ubuntu", "redhat", "all").
func GetOSPresetCommands(families ...string) []CommandDefinition {
	if len(families) == 0 {
		families = []string{"ubuntu", "redhat"}
	}
	wantAll := false
	wantUbuntu := false
	wantRedHat := false
	for _, f := range families {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "all", "*", "common", "linux":
			wantAll = true
		case "ubuntu", "debian":
			wantUbuntu = true
		case "redhat", "rhel", "rocky", "almalinux", "centos", "ubi":
			wantRedHat = true
		}
	}

	var out []CommandDefinition
	if wantAll || wantUbuntu {
		out = append(out, UbuntuPresetCommands()...)
	}
	if wantAll || wantRedHat {
		out = append(out, RedHatPresetCommands()...)
	}
	return out
}

// MergeOSPresets merges predefined OS commands into an existing slice of CommandDefinitions without duplicating names.
func MergeOSPresets(existing []CommandDefinition, families ...string) []CommandDefinition {
	seen := make(map[string]struct{}, len(existing))
	result := make([]CommandDefinition, 0, len(existing)+20)
	for _, cmd := range existing {
		seen[cmd.Name] = struct{}{}
		result = append(result, cmd)
	}
	for _, preset := range GetOSPresetCommands(families...) {
		if _, exists := seen[preset.Name]; !exists {
			seen[preset.Name] = struct{}{}
			result = append(result, preset)
		}
	}
	return result
}

// DetectHostOSFamily inspects /etc/redhat-release and /etc/os-release (or runtime.GOOS) to identify the host OS family.
func DetectHostOSFamily() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "ubuntu") || strings.Contains(lower, "debian") {
			return "ubuntu"
		}
		if strings.Contains(lower, "rhel") || strings.Contains(lower, "redhat") || strings.Contains(lower, "rocky") || strings.Contains(lower, "almalinux") || strings.Contains(lower, "centos") || strings.Contains(lower, "fedora") {
			return "redhat"
		}
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "redhat"
	}
	return runtime.GOOS
}
