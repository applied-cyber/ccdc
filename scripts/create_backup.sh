#!/usr/bin/env bash

set -euo pipefail

TARGET_ROOT=${1:-/toor}
BUSYBOX_BIN=${BUSYBOX_BIN:-$(command -v busybox || true)}
BASH_BIN=${BASH_BIN:-$(command -v bash || true)}
SH_BIN=${SH_BIN:-$(command -v sh || true)}

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

if [[ "$TARGET_ROOT" == "/" ]]; then
  echo "Refusing to use / as the target root." >&2
  exit 1
fi

if [[ -z "$BUSYBOX_BIN" || ! -x "$BUSYBOX_BIN" ]]; then
  echo "busybox was not found. Set BUSYBOX_BIN to the binary you want to copy." >&2
  exit 1
fi

if [[ -z "$BASH_BIN" || ! -x "$BASH_BIN" ]]; then
  echo "bash was not found. Set BASH_BIN to the binary you want to copy." >&2
  exit 1
fi

if [[ -z "$SH_BIN" || ! -x "$SH_BIN" ]]; then
  echo "sh was not found. Set SH_BIN to the binary you want to copy." >&2
  exit 1
fi

mkdir -p "$TARGET_ROOT"
mkdir -p \
  "$TARGET_ROOT"/{bin,dev,etc,home,proc,root,run,sbin,sys,tmp,usr/bin,usr/sbin,var/tmp}

chmod 1777 "$TARGET_ROOT/tmp" "$TARGET_ROOT/var/tmp"

install -m 0755 "$BUSYBOX_BIN" "$TARGET_ROOT/bin/busybox"

copy_dep() {
  local src=$1
  local rel=${src#/}
  local dst="$TARGET_ROOT/$rel"
  local resolved
  local link_target
  local logical_target

  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"

  if [[ -L "$src" ]]; then
    link_target=$(readlink "$src")
    if [[ "$link_target" = /* ]]; then
      logical_target=$link_target
    else
      logical_target=$(realpath -ms "$(dirname "$src")/$link_target")
    fi
    if [[ -n "$logical_target" && -e "$logical_target" && "$logical_target" != "$src" ]]; then
      copy_dep "$logical_target"
    fi

    resolved=$(readlink -f "$src")
    if [[ -n "$resolved" && -e "$resolved" && "$resolved" != "$src" ]]; then
      copy_dep "$resolved"
    fi
  fi
}

copy_binary_with_deps() {
  local src=$1
  local dst=$2
  local interp
  local resolved

  mkdir -p "$(dirname "$TARGET_ROOT/$dst")"
  resolved=$(readlink -f "$src")
  if [[ -z "$resolved" || ! -e "$resolved" ]]; then
    echo "Failed to resolve binary: $src" >&2
    exit 1
  fi

  cp -a "$resolved" "$TARGET_ROOT/$dst"

  interp=$(readelf -l "$resolved" 2>/dev/null | awk -F': ' '/Requesting program interpreter/ { gsub(/]/, "", $2); print $2 }')
  if [[ -n "${interp:-}" && -e "$interp" ]]; then
    copy_dep "$interp"
  fi

  while IFS= read -r dep; do
    [[ -n "$dep" && -e "$dep" ]] || continue
    copy_dep "$dep"
  done < <(
    ldd "$resolved" 2>/dev/null | awk '
      { gsub(/^[[:space:]]+/, "", $0) }
      /=> \// { print $3 }
      /^\// { print $1 }
    ' | sort -u
  )
}

copy_binary_with_deps "$BUSYBOX_BIN" "/bin/busybox"
copy_binary_with_deps "$BASH_BIN" "/bin/bash"
copy_binary_with_deps "$SH_BIN" "/bin/sh"

while IFS= read -r etc_path; do
  rel=${etc_path#/etc/}
  dst="$TARGET_ROOT/etc/$rel"

  if [[ -d "$etc_path" ]]; then
    mkdir -p "$dst"
  elif [[ -f "$etc_path" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$etc_path" "$dst"
  fi
done < <(find /etc ! -type l)

while IFS= read -r home_path; do
  rel=${home_path#/home/}
  dst="$TARGET_ROOT/home/$rel"

  if [[ "$home_path" == "/home" ]]; then
    continue
  fi

  mkdir -p "$dst"
done < <(find /home -type d 2>/dev/null || true)

while IFS= read -r applet; do
  [[ -n "$applet" ]] || continue
  [[ "$applet" == "bin/sh" || "$applet" == "bin/bash" ]] && continue

  applet_path=${applet#/}
  applet_dir=$(dirname "$applet_path")
  applet_name=$(basename "$applet_path")

  mkdir -p "$TARGET_ROOT/$applet_dir"
  ln -sfn /bin/busybox "$TARGET_ROOT/$applet_dir/$applet_name"
done < <("$BUSYBOX_BIN" --list-full)

