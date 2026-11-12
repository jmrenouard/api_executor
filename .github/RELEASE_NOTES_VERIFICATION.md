
---

### Cryptographic Checksum Verification & Asset Integrity

All release archives are cryptographically signed with SHA-256. Verification files are attached as release assets:
- **Unified Manifest**: `SHA256SUMS.txt` (attached as a release asset) contains SHA-256 hashes for all platform archives.
- **Individual Checksum Files**: An individual `<archive>.sha256` file is provided alongside each archive.

#### Verify via Unified Manifest (Linux / macOS)
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

#### Verify via Individual Checksum File (Linux / macOS)
```bash
sha256sum -c <archive-filename>.sha256
```

> **macOS Note**: If `sha256sum` is unavailable on macOS, use `shasum -a 256 -c SHA256SUMS.txt --ignore-missing` or `shasum -a 256 -c <archive-filename>.sha256`.

#### Verify via PowerShell (Windows)
```powershell
$archive = "<archive-filename>"

# Option A: Verify via individual .sha256 checksum file
$expectedHash = (Get-Content "$archive.sha256").Split(" ")[0]
$actualHash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
if ($actualHash -eq $expectedHash) { Write-Host "Checksum verification PASSED" -ForegroundColor Green } else { Write-Error "Checksum verification FAILED" }

# Option B: Verify via unified SHA256SUMS.txt manifest
$manifestHash = (Select-String -Path .\SHA256SUMS.txt -Pattern $archive).Line.Split(" ")[0]
if ($actualHash -eq $manifestHash) { Write-Host "Manifest verification PASSED" -ForegroundColor Green } else { Write-Error "Manifest verification FAILED" }
```
