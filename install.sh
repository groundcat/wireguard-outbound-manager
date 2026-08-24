#!/bin/sh
set -eu

APP=wireguard-outbound-manager
PREFIX=/usr/local
ETC=/etc/$APP
STATE=/var/lib/$APP
UNIT=/etc/systemd/system/$APP.service

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root"; }
supported_os() {
  [ -r /etc/os-release ] || die "cannot identify operating system"
  . /etc/os-release
  case "$ID" in debian|ubuntu) :;; *) die "only Debian and Ubuntu are supported";; esac
}
preflight() {
  need_root; supported_os
  command -v apt-get >/dev/null || die "apt-get is required"
  command -v systemctl >/dev/null || die "systemd is required"
  command -v iptables >/dev/null 2>&1 && iptables-save >/dev/null || true
  [ -d /sys/class/net ] || die "network namespace is unavailable"
  [ "$(df -Pk /usr/local | awk 'NR==2 {print $4}')" -gt 102400 ] || die "at least 100 MiB free space is required"
  printf 'preflight passed; no network changes were made\n'
}
install_app() {
  preflight
  umask 077
  mkdir -p "$STATE" "$ETC/tunnels"
  : > "$STATE/installed-packages"
  packages="golang-go wireguard-tools iproute2 iptables iputils-ping curl ca-certificates"
  missing=""
  for p in $packages; do
    if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then missing="$missing $p"; fi
  done
  if [ -n "$missing" ]; then
    printf 'installing required packages:%s\n' "$missing"
    DEBIAN_FRONTEND=noninteractive apt-get update
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing
    printf '%s\n' $missing > "$STATE/installed-packages"
  fi
  builddir=$(mktemp -d)
  trap 'rm -rf "$builddir"' EXIT INT TERM
  cp -R cmd internal go.mod "$builddir/"
  (cd "$builddir" && go test ./... && go build -trimpath -ldflags "-s -w" -o wgom ./cmd/wgom)
  install -o root -g root -m 0755 "$builddir/wgom" "$PREFIX/sbin/wgom"
  install -o root -g root -m 0644 deploy/wireguard-outbound-manager.service "$UNIT"
  systemctl daemon-reload
  printf '\nInstalled. Put root-only .conf files in %s/tunnels, then run:\n' "$ETC"
  printf '  wgom preflight\n  systemctl enable --now %s\n' "$APP"
  printf 'The installer intentionally did not enable routing.\n'
}
uninstall_app() {
  need_root
  systemctl disable --now "$APP" 2>/dev/null || true
  rm -f "$UNIT" "$PREFIX/sbin/wgom"
  systemctl daemon-reload
  rm -rf "/run/$APP"
  printf 'Removed program and service. Tunnel configs remain in %s.\n' "$ETC"
  if [ "${2:-}" = "--purge" ]; then
    rm -rf "$ETC" "$STATE"
    printf 'Purged configuration and installer state.\n'
  fi
}

case "${1:-}" in
  preflight) preflight;;
  install) install_app;;
  uninstall) uninstall_app "$@";;
  *) printf 'usage: sudo ./install.sh {preflight|install|uninstall [--purge]}\n' >&2; exit 2;;
esac
