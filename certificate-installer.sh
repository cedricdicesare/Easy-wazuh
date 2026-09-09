#!/bin/bash

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
EASY_WAZUH_ROOT="${EASY_WAZUH_ROOT:-/opt/wazuh}"
EASY_WAZUH_DOCKER_ROOT="${EASY_WAZUH_DOCKER_ROOT:-$EASY_WAZUH_ROOT/wazuh-docker}"
EASY_WAZUH_METADATA="${EASY_WAZUH_METADATA:-$EASY_WAZUH_ROOT/easy-wazuh/deployment.yaml}"
BACKUP_ROOT="${BACKUP_ROOT:-$EASY_WAZUH_ROOT/backups/certificates}"
TLS_TIMEOUT_SECONDS="${TLS_TIMEOUT_SECONDS:-20}"
TLS_CONNECT_HOST="${TLS_CONNECT_HOST:-127.0.0.1}"
SERVICE_WAIT_SECONDS="${SERVICE_WAIT_SECONDS:-120}"
TESTING="${EASY_WAZUH_CERT_INSTALLER_TESTING:-no}"
TMP_DIR=""

log() { printf '%s\n' "$*"; }
err() { printf 'Error: %s\n' "$*" >&2; }

cleanup_tmp() {
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    find "$TMP_DIR" -type f -exec chmod u+rw {} \; -exec rm -f {} \;
    find "$TMP_DIR" -depth -type d -exec rmdir {} \; 2>/dev/null || true
  fi
}

trap cleanup_tmp EXIT

require_root() {
  if [ "$TESTING" = "yes" ]; then
    return 0
  fi
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "this script must be run as root. Example: sudo ./$SCRIPT_NAME"
    exit 1
  fi
}

require_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    err "$name command was not found."
    exit 1
  fi
}

confirm() {
  local prompt="$1"
  local answer
  read -r -p "$prompt [y/N]: " answer
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

is_ipv4() {
  local value="$1" octet
  local -a octets
  [[ "$value" =~ ^([0-9]{1,3}[.]){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a octets <<< "$value"
  for octet in "${octets[@]}"; do
    [ "$octet" -le 255 ] || return 1
  done
}

is_ip_address() {
  local value="$1"
  is_ipv4 "$value" && return 0
  [[ "$value" == *:* ]] && return 0
  return 1
}

is_safe_service_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] && [[ "$value" != *..* ]]
}

make_tmp_dir() {
  if [ -z "${TMP_DIR:-}" ]; then
    TMP_DIR="$(mktemp -d)"
    chmod 700 "$TMP_DIR"
  fi
}

metadata_value() {
  local section="$1" key="$2" file="$3"
  awk -v section="$section" -v key="$key" '
    /^[[:space:]]*#/ { next }
    /^[^[:space:]][^:]*:[[:space:]]*$/ {
      current=$1
      sub(":", "", current)
      next
    }
    current == section {
      pattern="^[[:space:]]+" key ":[[:space:]]*"
      if ($0 ~ pattern) {
        sub(pattern, "", $0)
        gsub(/^"|"$/, "", $0)
        print $0
        exit
      }
    }
  ' "$file"
}

discover_compose_file() {
  if [ -f "$EASY_WAZUH_METADATA" ]; then
    local stack_dir compose_name
    stack_dir="$(metadata_value deployment stack_directory "$EASY_WAZUH_METADATA")"
    compose_name="$(metadata_value deployment compose_file "$EASY_WAZUH_METADATA")"
    if [ -n "$stack_dir" ] && [ -n "$compose_name" ] && [ -f "$stack_dir/$compose_name" ]; then
      printf '%s\n' "$stack_dir/$compose_name"
      return 0
    fi
  fi

  if [ -f "$EASY_WAZUH_DOCKER_ROOT/multi-node/docker-compose.yml" ]; then
    printf '%s\n' "$EASY_WAZUH_DOCKER_ROOT/multi-node/docker-compose.yml"
    return 0
  fi
  if [ -f "$EASY_WAZUH_DOCKER_ROOT/single-node/docker-compose.yml" ]; then
    printf '%s\n' "$EASY_WAZUH_DOCKER_ROOT/single-node/docker-compose.yml"
    return 0
  fi
  return 1
}

compose_project_dir() {
  dirname "$1"
}

compose_cmd() {
  local compose_file="$1"
  shift
  docker compose --project-directory "$(compose_project_dir "$compose_file")" -f "$compose_file" "$@"
}

compose_services() {
  local compose_file="$1"
  awk '
    /^services:[[:space:]]*$/ { in_services=1; next }
    in_services && /^[^[:space:]][^:]*:/ { exit }
    in_services && /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/ {
      line=$0
      sub(/^[[:space:]]*/, "", line)
      sub(/:.*/, "", line)
      print line
    }
  ' "$compose_file"
}

compose_service_block() {
  local compose_file="$1" service="$2"
  awk -v service="$service" '
    $0 ~ "^[[:space:]]{2}" service ":[[:space:]]*$" { in_service=1; print; next }
    in_service && /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/ { exit }
    in_service { print }
  ' "$compose_file"
}

service_publishes_port() {
  local compose_file="$1" service="$2" port="$3"
  compose_service_block "$compose_file" "$service" | grep -Eq "['\"]?([0-9.]+:)?$port:$port(/tcp)?['\"]?|['\"]?([0-9.]+:)?$port:[0-9]+(/tcp)?['\"]?"
}

find_service_for_host_port() {
  local compose_file="$1" port="$2" service
  while IFS= read -r service; do
    if service_publishes_port "$compose_file" "$service" "$port"; then
      printf '%s\n' "$service"
      return 0
    fi
  done < <(compose_services "$compose_file")
  return 1
}

service_image_contains() {
  local compose_file="$1" service="$2" needle="$3"
  compose_service_block "$compose_file" "$service" | grep -Eq "image:[[:space:]]*.*$needle"
}

resolve_bind_source_for_target() {
  local compose_file="$1" service="$2" target="$3" base
  base="$(compose_project_dir "$compose_file")"
  compose_service_block "$compose_file" "$service" | awk -v target="$target" '
    /^[[:space:]]+-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]+-[[:space:]]*/, "", line)
      gsub(/^"|"$/, "", line)
      gsub(/^'\''|'\''$/, "", line)
      split(line, parts, ":")
      if (length(parts) >= 2 && parts[2] == target) {
        print parts[1]
        exit
      }
    }
  ' | while IFS= read -r source; do
    case "$source" in
      ./*) printf '%s/%s\n' "$base" "${source#./}" ;;
      /*) printf '%s\n' "$source" ;;
      *) return 1 ;;
    esac
  done
}

compose_environment_value() {
  local compose_file="$1" service="$2" key="$3"
  compose_service_block "$compose_file" "$service" | awk -v key="$key" '
    /^[[:space:]]+-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]+-[[:space:]]*/, "", line)
      gsub(/^"|"$/, "", line)
      gsub(/^'\''|'\''$/, "", line)
      if (index(line, key "=") == 1) {
        sub(key "=", "", line)
        gsub(/^"|"$/, "", line)
        print line
        exit
      }
    }
  '
}

discover_public_endpoint() {
  local compose_file="$1" meta cert_meta
  cert_meta="$(compose_project_dir "$compose_file")/config/wazuh_indexer_ssl_certs/.easy-wazuh-cert-endpoint"
  if [ -f "$cert_meta" ]; then
    meta="$(sed -n 's/.*endpoint=\([^;]*\).*/\1/p' "$cert_meta" | head -n 1)"
    if [ -n "$meta" ]; then
      printf '%s\n' "$meta"
      return 0
    fi
  fi
  hostname -f 2>/dev/null || hostname
}

certificate_fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^sha256 Fingerprint=//;s/^SHA256 Fingerprint=//'
}

tls_connect_target() {
  local host="$1"
  if is_ip_address "$host"; then
    printf '%s\n' "$host"
  else
    printf '%s\n' "$TLS_CONNECT_HOST"
  fi
}

read_served_certificate() {
  local host="$1" port="$2" output="$3" connect_host
  connect_host="$(tls_connect_target "$host")"
  timeout "$TLS_TIMEOUT_SECONDS" openssl s_client -connect "$connect_host:$port" -servername "$host" -showcerts </dev/null 2>/dev/null |
    awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}' > "$output"
  [ -s "$output" ]
}

served_certificate_fingerprint() {
  local host="$1" port="$2" tmp
  make_tmp_dir
  tmp="$TMP_DIR/served-$port.pem"
  read_served_certificate "$host" "$port" "$tmp" || return 1
  certificate_fingerprint "$tmp"
}

print_certificate_info() {
  local cert="$1"
  openssl x509 -in "$cert" -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256
  printf 'Key type: '
  openssl x509 -in "$cert" -noout -pubkey | openssl pkey -pubin -noout -text 2>/dev/null | sed -n '1p'
}

normalize_leaf_and_chain() {
  local cert_file="$1" chain_file="${2:-}" leaf_out="$3" chain_out="$4"
  awk '
    /-----BEGIN CERTIFICATE-----/ { count++; in_cert=1 }
    in_cert && count == 1 { print }
    /-----END CERTIFICATE-----/ && count == 1 { in_cert=0 }
  ' "$cert_file" > "$leaf_out"

  awk '
    /-----BEGIN CERTIFICATE-----/ { count++; in_cert=1 }
    in_cert && count > 1 { print }
    /-----END CERTIFICATE-----/ && count > 1 { in_cert=0 }
  ' "$cert_file" > "$chain_out"

  if [ -n "$chain_file" ]; then
    cat "$chain_file" >> "$chain_out"
  fi
}

validate_pem_certificate() {
  local cert="$1"
  [ -r "$cert" ] || { err "certificate is not readable: $cert"; return 1; }
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || { err "certificate is not a readable PEM X.509 certificate."; return 1; }
}

validate_private_key() {
  local key="$1"
  [ -r "$key" ] || { err "private key is not readable: $key"; return 1; }
  if ! openssl pkey -in "$key" -noout -passin pass: >/dev/null 2>&1; then
    if grep -q "ENCRYPTED" "$key" 2>/dev/null; then
      err "encrypted private keys are not supported in V1. Export an unencrypted PEM key for Docker restart safety."
    else
      err "private key is not a readable PEM private key."
    fi
    return 1
  fi
}

public_key_digest_from_cert() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -binary |
    openssl base64 -A
}

public_key_digest_from_key() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null |
    openssl dgst -sha256 -binary |
    openssl base64 -A
}

validate_cert_key_match() {
  local cert="$1" key="$2"
  [ "$(public_key_digest_from_cert "$cert")" = "$(public_key_digest_from_key "$key")" ] || {
    err "certificate and private key do not match."
    return 1
  }
}

validate_cert_dates() {
  local cert="$1"
  if ! openssl x509 -in "$cert" -checkend 0 -noout >/dev/null 2>&1; then
    err "certificate is expired."
    return 1
  fi
  local not_before epoch_now epoch_before
  not_before="$(openssl x509 -in "$cert" -noout -startdate | sed 's/^notBefore=//')"
  epoch_now="$(date +%s)"
  epoch_before="$(date -d "$not_before" +%s 2>/dev/null || date -jf "%b %e %T %Y %Z" "$not_before" +%s 2>/dev/null || echo 0)"
  if [ "$epoch_before" -gt "$epoch_now" ]; then
    err "certificate is not valid yet."
    return 1
  fi
}

warn_if_expiring_soon() {
  local cert="$1"
  if ! openssl x509 -in "$cert" -checkend 2592000 -noout >/dev/null 2>&1; then
    log "Warning: certificate expires in less than 30 days."
    confirm "Continue anyway?" || return 1
  fi
}

validate_hostname_coverage() {
  local cert="$1" name="$2"
  local output
  if is_ip_address "$name"; then
    output="$(openssl x509 -in "$cert" -noout -checkip "$name" 2>/dev/null || true)"
    grep -Fq "does match" <<< "$output" || {
      err "certificate does not cover IP SAN: $name"
      return 1
    }
  else
    output="$(openssl x509 -in "$cert" -noout -checkhost "$name" 2>/dev/null || true)"
    grep -Fq "does match" <<< "$output" || {
      err "certificate does not cover DNS SAN: $name"
      return 1
    }
  fi
}

validate_chain_if_present() {
  local leaf="$1" chain="$2"
  [ -s "$chain" ] || return 0
  openssl verify -partial_chain -trusted "$chain" "$leaf" >/dev/null 2>&1 || {
    err "certificate chain is not coherent. Provide a correct fullchain or intermediate chain."
    return 1
  }
}

validate_certificate_bundle() {
  local cert_file="$1" key_file="$2" chain_file="${3:-}"
  shift 3 || true
  local names=("$@")
  local leaf chain name
  make_tmp_dir
  leaf="$TMP_DIR/leaf.pem"
  chain="$TMP_DIR/chain.pem"

  case "$cert_file" in *.p12|*.P12|*.pfx|*.PFX)
    err "PKCS#12 files are not supported in V1. Export certificate/fullchain and private key as PEM."
    return 1
    ;;
  esac
  case "$key_file" in *.p12|*.P12|*.pfx|*.PFX)
    err "PKCS#12 files are not supported in V1. Export certificate/fullchain and private key as PEM."
    return 1
    ;;
  esac

  normalize_leaf_and_chain "$cert_file" "$chain_file" "$leaf" "$chain"
  validate_pem_certificate "$leaf" || return 1
  validate_private_key "$key_file" || return 1
  validate_cert_dates "$leaf" || return 1
  validate_cert_key_match "$leaf" "$key_file" || return 1
  validate_chain_if_present "$leaf" "$chain" || return 1
  cat "$leaf" "$chain" > "$TMP_DIR/server-certificate.pem"
  chmod 600 "$TMP_DIR/server-certificate.pem"
  for name in "${names[@]}"; do
    [ -n "$name" ] || continue
    validate_hostname_coverage "$leaf" "$name" || return 1
  done
  warn_if_expiring_soon "$leaf" || return 1
  print_certificate_info "$leaf"
}

copy_with_mode() {
  local source="$1" target="$2" mode="$3" owner_group="${4:-}"
  install -m "$mode" "$source" "$target"
  if [ -n "$owner_group" ]; then
    chown "$owner_group" "$target"
  fi
}

file_owner_group_mode() {
  local file="$1"
  stat -c '%u:%g %a' "$file"
}

backup_file_with_metadata() {
  local file="$1" dest_dir="$2" label="$3"
  mkdir -p "$dest_dir"
  chmod 700 "$dest_dir"
  if [ -f "$file" ]; then
    cp -p "$file" "$dest_dir/$label"
    stat -c "$label|%n|%u|%g|%a" "$file" >> "$dest_dir/permissions.txt"
    case "$label" in
      *key*) chmod 600 "$dest_dir/$label" ;;
    esac
  fi
}

create_backup_dir() {
  local target="$1" ts dir
  ts="$(date +%Y%m%d-%H%M%S)"
  dir="$BACKUP_ROOT/$ts"
  mkdir -p "$dir/$target" "$dir/metadata"
  chmod 700 "$BACKUP_ROOT" "$dir" "$dir/$target" "$dir/metadata"
  printf '%s\n' "$dir"
}

restore_file_entry() {
  local backup_file="$1" target="$2"
  [ -f "$backup_file" ] || return 0
  cp -p "$backup_file" "$target"
}

restore_permissions_from_metadata() {
  local metadata_file="$1" label="$2" target="$3"
  local line uid gid mode
  [ -f "$metadata_file" ] || return 0
  line="$(awk -F'|' -v label="$label" '$1 == label { print; exit }' "$metadata_file")"
  [ -n "$line" ] || return 0
  uid="$(awk -F'|' '{print $3}' <<< "$line")"
  gid="$(awk -F'|' '{print $4}' <<< "$line")"
  mode="$(awk -F'|' '{print $5}' <<< "$line")"
  case "$mode" in
    777|666) err "refusing to restore dangerous permissions on $target"; return 1 ;;
  esac
  chown "$uid:$gid" "$target"
  chmod "$mode" "$target"
}

install_dashboard_files() {
  local compose_file="$1" service="$2" cert_file="$3" key_file="$4" backup_dir="$5"
  local cert_target key_target owner_cert owner_key
  cert_target="$(resolve_bind_source_for_target "$compose_file" "$service" "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem")"
  key_target="$(resolve_bind_source_for_target "$compose_file" "$service" "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem")"
  [ -n "$cert_target" ] && [ -n "$key_target" ] || { err "Dashboard TLS certificate bind mounts were not found."; return 1; }
  [[ "$cert_target" != *root-ca.pem* && "$key_target" != *root-ca.pem* ]] || { err "refusing to modify root-ca.pem."; return 1; }
  [ -f "$cert_target" ] && [ -f "$key_target" ] || { err "Dashboard certificate files do not exist on host."; return 1; }

  backup_file_with_metadata "$cert_target" "$backup_dir/dashboard" "certificate.pem"
  backup_file_with_metadata "$key_target" "$backup_dir/dashboard" "private-key.pem"
  printf 'certificate_target=%s\nprivate_key_target=%s\nservice=%s\n' "$cert_target" "$key_target" "$service" > "$backup_dir/metadata/dashboard.env"
  chmod 600 "$backup_dir/metadata/dashboard.env"

  owner_cert="$(file_owner_group_mode "$cert_target")"
  owner_key="$(file_owner_group_mode "$key_target")"
  copy_with_mode "$cert_file" "$cert_target" "${owner_cert##* }" "${owner_cert%% *}"
  copy_with_mode "$key_file" "$key_target" "600" "${owner_key%% *}"
}

restore_dashboard_files() {
  local backup_dir="$1"
  local meta cert_target key_target
  meta="$backup_dir/metadata/dashboard.env"
  [ -f "$meta" ] || { err "Dashboard backup metadata not found."; return 1; }
  cert_target="$(sed -n 's/^certificate_target=//p' "$meta")"
  key_target="$(sed -n 's/^private_key_target=//p' "$meta")"
  restore_file_entry "$backup_dir/dashboard/certificate.pem" "$cert_target"
  restore_file_entry "$backup_dir/dashboard/private-key.pem" "$key_target"
  restore_permissions_from_metadata "$backup_dir/dashboard/permissions.txt" "certificate.pem" "$cert_target"
  restore_permissions_from_metadata "$backup_dir/dashboard/permissions.txt" "private-key.pem" "$key_target"
}

restart_target() {
  local compose_file="$1" service="$2"
  is_safe_service_name "$service" || { err "unsafe service name: $service"; return 1; }
  compose_cmd "$compose_file" restart "$service"
}

service_running() {
  local compose_file="$1" service="$2" deadline
  deadline=$(($(date +%s) + SERVICE_WAIT_SECONDS))
  while true; do
    if compose_cmd "$compose_file" ps --status running -q "$service" | grep -q .; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      err "service $service did not reach running state within ${SERVICE_WAIT_SECONDS}s."
      return 1
    fi
    sleep 2
  done
}

verify_endpoint_tls() {
  local host="$1" port="$2" expected_fingerprint="$3"
  local served cert_file deadline last_error
  make_tmp_dir
  cert_file="$TMP_DIR/verify-$port.pem"
  deadline=$(($(date +%s) + SERVICE_WAIT_SECONDS))
  last_error="TLS handshake failed"
  while true; do
    if read_served_certificate "$host" "$port" "$cert_file"; then
      served="$(certificate_fingerprint "$cert_file")"
      if [ "$served" = "$expected_fingerprint" ] && validate_hostname_coverage "$cert_file" "$host"; then
        return 0
      fi
      last_error="served certificate fingerprint or hostname did not match expected certificate"
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      err "$last_error on $host:$port via $(tls_connect_target "$host") within ${SERVICE_WAIT_SECONDS}s."
      return 1
    fi
    sleep 2
  done
}

dashboard_required_names() {
  local compose_file="$1"
  discover_public_endpoint "$compose_file"
}

discover_targets() {
  local compose_file="$1" dashboard_service port443_service
  port443_service="$(find_service_for_host_port "$compose_file" 443 || true)"
  [ -n "$port443_service" ] || { err "no Compose service publishes host port 443."; return 1; }
  if service_image_contains "$compose_file" "$port443_service" "wazuh-dashboard"; then
    dashboard_service="$port443_service"
  else
    err "host port 443 is published by $port443_service, not by Wazuh Dashboard. This topology is not supported in V1."
    return 1
  fi
  printf 'dashboard=%s
' "$dashboard_service"
}
install_dashboard_certificate() {
  local compose_file="$1" cert_file="$2" key_file="$3" chain_file="${4:-}"
  local targets dashboard_service public_endpoint desired_fp current_fp backup_dir
  targets="$(discover_targets "$compose_file")"
  dashboard_service="$(sed -n 's/^dashboard=//p' <<< "$targets")"
  public_endpoint="$(dashboard_required_names "$compose_file")"
  validate_certificate_bundle "$cert_file" "$key_file" "$chain_file" "$public_endpoint"
  desired_fp="$(certificate_fingerprint "$TMP_DIR/leaf.pem")"
  current_fp="$(served_certificate_fingerprint "$public_endpoint" 443 || true)"
  if [ "$current_fp" = "$desired_fp" ]; then
    log "The requested certificate is already installed."
    log "No change required."
    return 0
  fi
  confirm "Install / replace Dashboard certificate for $public_endpoint?" || { log "No change was performed."; return 0; }
  backup_dir="$(create_backup_dir dashboard)"
  if install_dashboard_files "$compose_file" "$dashboard_service" "$TMP_DIR/server-certificate.pem" "$key_file" "$backup_dir" &&
     restart_target "$compose_file" "$dashboard_service" &&
     service_running "$compose_file" "$dashboard_service" &&
     verify_endpoint_tls "$public_endpoint" 443 "$desired_fp"; then
    log "SUCCESS: Dashboard certificate installed."
  else
    err "Dashboard installation failed. Rolling back."
    restore_dashboard_files "$backup_dir" || true
    restart_target "$compose_file" "$dashboard_service" || true
    if [ -n "$current_fp" ]; then
      verify_endpoint_tls "$public_endpoint" 443 "$current_fp" || true
    fi
    return 1
  fi
}

show_current_certificates() {
  local compose_file="$1" endpoint
  endpoint="$(discover_public_endpoint "$compose_file")"
  log "Dashboard endpoint: https://$endpoint"
  read_served_certificate "$endpoint" 443 "$TMP_DIR/dashboard-served.pem" || true
  [ -s "$TMP_DIR/dashboard-served.pem" ] && print_certificate_info "$TMP_DIR/dashboard-served.pem" || log "Dashboard certificate could not be read from $(tls_connect_target "$endpoint"):443 with SNI $endpoint."
}
list_backups() {
  [ -d "$BACKUP_ROOT" ] || return 0
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort
}

restore_backup_menu() {
  local compose_file="$1" backup service
  log "Available backups:"
  list_backups | nl -ba
  read -r -p "Backup path to restore: " backup
  [ -d "$backup" ] || { err "backup directory not found."; return 1; }
  [ -f "$backup/metadata/dashboard.env" ] || { err "selected backup does not contain a Dashboard certificate backup."; return 1; }
  confirm "Restore Dashboard certificate from $backup?" || { log "No change was performed."; return 0; }
  service="$(sed -n 's/^service=//p' "$backup/metadata/dashboard.env")"
  restore_dashboard_files "$backup"
  restart_target "$compose_file" "$service"
  service_running "$compose_file" "$service"
  log "Restore completed. Run Show current Dashboard certificate to verify served TLS certificate."
}
prompt_certificate_inputs() {
  CERT_INPUT=""
  KEY_INPUT=""
  CHAIN_INPUT=""
  read -r -p "Path to certificate or fullchain PEM file: " CERT_INPUT
  read -r -p "Path to private key PEM file: " KEY_INPUT
  read -r -p "Path to intermediate chain PEM file (optional, press Enter to skip): " CHAIN_INPUT
}

main_menu() {
  local compose_file choice
  require_root
  require_command openssl
  require_command docker
  if ! docker compose version >/dev/null 2>&1; then
    err "Docker Compose plugin was not found."
    exit 1
  fi
  compose_file="$(discover_compose_file)" || { err "Easy-Wazuh installation not found under $EASY_WAZUH_DOCKER_ROOT."; exit 1; }
  make_tmp_dir

  while true; do
    log "=================================================="
    log " Easy-Wazuh TLS certificate installer"
    log "=================================================="
    log ""
    log "1) Show current Dashboard certificate"
    log "2) Install / replace Dashboard certificate"
    log "3) Restore previous Dashboard certificate"
    log "4) Exit"
    read -r -p "Choose an option [1-4]: " choice
    case "$choice" in
      1) show_current_certificates "$compose_file" ;;
      2) prompt_certificate_inputs; install_dashboard_certificate "$compose_file" "$CERT_INPUT" "$KEY_INPUT" "$CHAIN_INPUT" ;;
      3) restore_backup_menu "$compose_file" ;;
      4) exit 0 ;;
      *) log "Please enter 1, 2, 3 or 4." ;;
    esac
    log ""
  done
}

if [ "$TESTING" != "yes" ]; then
  main_menu "$@"
fi
