#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

escape_value() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\\"/g'
}

printf 'NetScope API key setup wizard\n'
printf 'This creates a .env file for Docker and optionally adds values to your shell startup file.\n\n'

if [ -f .env ]; then
  backup=".env.bak.$(date +%Y%m%d%H%M%S)"
  cp .env "$backup"
  printf 'Existing .env file backed up to %s\n' "$backup"
fi

read -rp 'Shodan API key (leave blank to skip): ' shodan_api_key
read -rp 'Censys ID (leave blank to skip): ' censys_id
read -rsp 'Censys Secret (leave blank to skip): ' censys_secret
printf '\n'
read -rp 'Optional NetScope API auth key SCANNER_API_KEY (leave blank to skip): ' scanner_api_key

cat > .env <<EOF
SHODAN_API_KEY="$(escape_value "$shodan_api_key")"
CENSYS_ID="$(escape_value "$censys_id")"
CENSYS_SECRET="$(escape_value "$censys_secret")"
SCANNER_API_KEY="$(escape_value "$scanner_api_key")"
EOF

printf '\n.env file created successfully.\n'

read -rp 'Do you want to add these keys to your shell startup file (~/.bashrc or ~/.zshrc)? [y/N]: ' add_shell
if [[ "$add_shell" =~ ^[Yy] ]]; then
  shell_rc="${HOME}/.bashrc"
  if [ -n "${ZSH_VERSION:-}" ] || [[ "${SHELL:-}" == *"zsh"* ]]; then
    shell_rc="${HOME}/.zshrc"
  elif [[ "${SHELL:-}" == *"fish"* ]]; then
    shell_rc="${HOME}/.config/fish/config.fish"
  fi

  if [[ "${SHELL:-}" == *"fish"* ]]; then
    cat >> "$shell_rc" <<EOF
# NetScope API keys
set -x SHODAN_API_KEY "${shodan_api_key}"
set -x CENSYS_ID "${censys_id}"
set -x CENSYS_SECRET "${censys_secret}"
set -x SCANNER_API_KEY "${scanner_api_key}"
EOF
  else
    cat >> "$shell_rc" <<EOF
# NetScope API keys
export SHODAN_API_KEY="${shodan_api_key}"
export CENSYS_ID="${censys_id}"
export CENSYS_SECRET="${censys_secret}"
export SCANNER_API_KEY="${scanner_api_key}"
EOF
  fi
  printf 'Environment exports added to %s\n' "$shell_rc"
  printf 'Run `source %s` or open a new shell to load them.\n' "$shell_rc"
fi

printf '\nSetup complete.\n'
printf 'Docker Compose now uses .env for container environment values.\n'
printf 'Run `docker compose up --build` or `./docker-up.sh` to start NetScope.\n'
