#!/usr/bin/env bash
# Install missing redbreach tools in WSL/Kali. Run from anywhere: bash install_bounty_tools.sh
# Locations (mostly automatic):
#   go install  -> ~/go/bin        (on PATH)
#   apt         -> /usr/bin        (system-wide, needs sudo)
#   pipx        -> ~/.local/bin    (on PATH)
# The only cloned tools go under $TOOLS_DIR (override: TOOLS_DIR=/opt/tools bash install_bounty_tools.sh)
set -u
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
mkdir -p "$TOOLS_DIR"

# --- Go tools (no sudo; ~/go/bin on PATH) ---
go install github.com/sa7mon/s3scanner@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/owasp-amass/amass/v4/...@master
# trufflehog has replace directives -> go install fails; use the release script:
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/go/bin

# --- apt packages (sudo) ---
sudo apt update
sudo apt install -y masscan python3-pip pipx libpcap-dev awscli nodejs npm seclists

# --- naabu needs libpcap-dev (installed above) then go build ---
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# --- Python tools (pipx, isolated) ---
pipx ensurepath
pipx install arjun
pipx install wafw00f
pipx install frida-tools
pipx install objection
pipx install semgrep

# --- gcloud (snap is simplest on WSL) ---
sudo snap install google-cloud-cli --classic

# --- cloudsploit (node) ---
# The "N vulnerabilities" npm prints are in cloudsploit's own deps; it is a local
# scanner, not an exposed service. Do NOT run `npm audit fix --force` (breaks majors).
git clone https://github.com/aquasecurity/cloudsploit "$TOOLS_DIR/cloudsploit"
npm --prefix "$TOOLS_DIR/cloudsploit" install --no-audit --no-fund

# --- MobSF (OPTIONAL; static APK analysis already works via apktool+jadx without it) ---
if command -v docker >/dev/null 2>&1; then
  docker pull opensecurity/mobile-security-framework-mobsf:latest
else
  echo "docker not found -> skipping MobSF docker image."
  echo "Options: install Docker Desktop (WSL integration), OR run MobSF from source:"
  echo "  git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF \"$TOOLS_DIR/mobsf\" && cd \"$TOOLS_DIR/mobsf\" && ./setup.sh"
fi
