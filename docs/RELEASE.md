# Release & distribution

## TL;DR

Three distribution paths, increasing in trust and friction-free-ness:

1. **`cargo install envs-cli`** — works for any Rust user, no Apple Developer ID required, no Gatekeeper warning if installed via cargo.
2. **`brew install envs`** (homebrew tap) — works for any macOS user, brew strips the quarantine attribute on install.
3. **Signed + notarized binaries** — required for distribution as raw `.tar.gz` downloads. Requires Apple Developer ID ($99/yr).

## Building a release

```bash
cd ~/www/labs/envs/
cargo build --release --workspace
```

Produces three binaries in `target/release/`:
- `envs` (~2 MB)
- `envsd` (~2 MB)
- `envs-prompt` (~1.5 MB)

## Codesigning (optional, for paths #3)

```bash
# Skip codesign (default — fine for paths #1 and #2):
scripts/codesign.sh   # warns and exits 0

# Codesign only:
ENVS_APPLE_TEAM_ID=ABC1234567 scripts/codesign.sh

# Codesign + notarize:
ENVS_APPLE_TEAM_ID=ABC1234567 ENVS_NOTARIZE=1 scripts/codesign.sh
```

### One-time notarization setup

Before the first `ENVS_NOTARIZE=1` run:

```bash
# Generate an app-specific password at https://appleid.apple.com → Sign-In and Security
# Then store credentials in keychain:
xcrun notarytool store-credentials envs-notary \
    --apple-id "your-apple-id@example.com" \
    --team-id "ABC1234567" \
    --password "abcd-efgh-ijkl-mnop"
```

The script reads these stored credentials by profile name `envs-notary` (overridable via `ENVS_NOTARY_PROFILE`).

### What codesign does

- Sets the **hardened runtime** (`--options runtime`) — required for notarization
- Adds a **timestamp** — required for distribution
- Signs with **Developer ID Application** identity — required for Gatekeeper to allow non-App-Store binaries
- Sets the bundle identifier (`com.fgribreau.envs.<binary>`)

### What notarize does

- Uploads each binary (zipped) to Apple's notary service
- Waits for Apple to scan and approve (~1-3 minutes per binary)
- Apple issues a notarization ticket attached to the binary's hash

Notarization ≠ stapling. Stapling embeds the ticket in the artifact for offline verification. Apple's `stapler` tool only works on `.app`, `.dmg`, `.pkg` containers — NOT raw binaries. For raw `envs`/`envsd`/`envs-prompt` distributed via `.tar.gz`, the ticket lives in Apple's notary database; Gatekeeper checks online when the user first runs the binary. This works fine on macOS 10.14+.

## Distribution paths

### A. crates.io (path #1)

```bash
cargo publish --package envs-proto
cargo publish --package envs-cli         # publishes binary `envs`
cargo publish --package envs-daemon      # publishes binary `envsd`
cargo publish --package envs-prompt      # publishes binary `envs-prompt`
```

Users install with:
```bash
cargo install envs-cli envs-daemon envs-prompt
```

### B. Homebrew tap (path #2)

Create `homebrew-fgribreau` repo with `Formula/envs.rb`:

```ruby
class Envs < Formula
  desc "Lulu-style firewall for environment variables (Bitwarden + TouchID)"
  homepage "https://github.com/fgribreau/envs"
  url "https://github.com/fgribreau/envs/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "..."
  license "MIT"

  depends_on "rust" => :build
  depends_on "rbw" => :recommended

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/envs-cli"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/envs-daemon"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/envs-prompt"
  end

  test do
    assert_match "envs", shell_output("#{bin}/envs --version")
  end
end
```

Tap + install:
```bash
brew tap fgribreau/fgribreau
brew install envs
```

### C. Pre-built `.tar.gz` releases (path #3)

```bash
# 1. Build + codesign + notarize:
cargo build --release --workspace
ENVS_APPLE_TEAM_ID=ABC1234567 ENVS_NOTARIZE=1 scripts/codesign.sh

# 2. Bundle:
mkdir -p /tmp/envs-v0.3.0/bin
cp target/release/{envs,envsd,envs-prompt} /tmp/envs-v0.3.0/bin/
cp packaging/com.fgribreau.envsd.plist.template /tmp/envs-v0.3.0/
cp README.md LICENSE /tmp/envs-v0.3.0/
cd /tmp && tar czf envs-v0.3.0-darwin-arm64.tar.gz envs-v0.3.0/

# 3. Upload to GitHub Releases:
gh release create v0.3.0 envs-v0.3.0-darwin-arm64.tar.gz \
    --title "envs v0.3.0" \
    --notes "..."
```

## Verifying a release

```bash
# Verify codesign:
codesign --verify --strict --verbose=2 ~/www/labs/envs/target/release/envs
codesign -dv --verbose=4 ~/www/labs/envs/target/release/envs 2>&1 | grep TeamIdentifier

# Verify notarization (online check, requires network):
spctl --assess --type execute --verbose=4 ~/www/labs/envs/target/release/envs
```

Expected output for a properly signed + notarized binary:
- `valid on disk` (codesign verify)
- `TeamIdentifier=ABC1234567` (codesign show)
- `accepted` + `source=Notarized Developer ID` (spctl)
