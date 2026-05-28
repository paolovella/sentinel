#!/bin/sh
# Vellaveto installer
#
#   curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh | sh
#
# Environment overrides:
#   VELLAVETO_VERSION       Pin a specific version (default: latest GitHub release)
#   VELLAVETO_INSTALL_DIR   Install location (default: $HOME/.local/bin)
#   VELLAVETO_BINARY        Install one binary only (default: all 4)
#                           Valid: vellaveto, vellaveto-proxy, vellaveto-shield, vellaveto-http-proxy
#   VELLAVETO_FORCE         Overwrite existing install without prompting (default: 0)
#   VELLAVETO_QUIET         Suppress non-error output (default: 0)
#
# Exit codes:
#   0  success
#   1  generic error
#   2  unsupported platform
#   3  network error
#   4  checksum verification failed
#   5  missing required tool (curl/wget, tar, sha256sum/shasum)

set -eu

REPO="paolovella/vellaveto"
ALL_BINARIES="vellaveto vellaveto-proxy vellaveto-shield vellaveto-http-proxy"

# ───────────────────────────── output helpers ─────────────────────────────

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET="$(printf '\033[0m')"
    C_BOLD="$(printf '\033[1m')"
    C_GREEN="$(printf '\033[32m')"
    C_YELLOW="$(printf '\033[33m')"
    C_RED="$(printf '\033[31m')"
    C_DIM="$(printf '\033[2m')"
else
    C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""
fi

log() {
    if [ "${VELLAVETO_QUIET:-0}" != "1" ]; then
        printf '%s▸%s %s\n' "$C_GREEN" "$C_RESET" "$1" >&2
    fi
}

warn() {
    printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2
}

err() {
    printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$1" >&2
}

die() {
    err "$1"
    exit "${2:-1}"
}

# ─────────────────────── prerequisite tool detection ──────────────────────

DOWNLOAD=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOAD="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOAD="wget"
else
    die "Need curl or wget to download Vellaveto. Install one and re-run." 5
fi

command -v tar >/dev/null 2>&1 || die "Need tar to extract the archive." 5

SHA256=""
if command -v sha256sum >/dev/null 2>&1; then
    SHA256="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256="shasum -a 256"
else
    die "Need sha256sum or shasum to verify checksums. Install one and re-run." 5
fi

# ────────────────────────── platform detection ────────────────────────────

detect_target() {
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "$uname_s" in
        Linux)  os="unknown-linux-musl" ;;
        Darwin) os="apple-darwin" ;;
        MINGW*|MSYS*|CYGWIN*)
            die "Windows is not yet supported by this installer.
   Install via WSL, or download a binary manually from
   https://github.com/$REPO/releases/latest" 2
            ;;
        *) die "Unsupported OS: $uname_s" 2 ;;
    esac

    case "$uname_m" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "Unsupported architecture: $uname_m" 2 ;;
    esac

    echo "${arch}-${os}"
}

# ───────────────────────── download wrappers ──────────────────────────────

# Stream a URL to stdout. Use only for small files (checksums, version JSON).
fetch_stdout() {
    url="$1"
    if [ "$DOWNLOAD" = "curl" ]; then
        curl -fsSL --proto '=https' --tlsv1.2 --max-time 30 --retry 2 "$url"
    else
        wget -qO- --max-redirect=5 --timeout=30 --tries=3 "$url"
    fi
}

# Download URL to a file path. Used for the tarball.
fetch_file() {
    url="$1"
    dest="$2"
    if [ "$DOWNLOAD" = "curl" ]; then
        curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 --retry 2 \
             -o "$dest" "$url"
    else
        wget -q --max-redirect=5 --timeout=300 --tries=3 -O "$dest" "$url"
    fi
}

# ──────────────────────── version resolution ──────────────────────────────

resolve_version() {
    if [ -n "${VELLAVETO_VERSION:-}" ]; then
        # Strip leading 'v' if present so the tag and archive names line up.
        echo "${VELLAVETO_VERSION#v}"
        return
    fi

    # GitHub's redirect on /releases/latest gives us the tag without hitting the API.
    # Falling back to the API requires a token after a few unauthenticated requests.
    url="https://github.com/$REPO/releases/latest"
    if [ "$DOWNLOAD" = "curl" ]; then
        tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url" 2>/dev/null \
               | sed -n 's@.*/tag/v\?\(.*\)@\1@p' \
               | tr -d '\r\n')"
    else
        tag="$(wget --spider --max-redirect=5 -S "$url" 2>&1 \
               | sed -n 's@^[[:space:]]*Location:.*/tag/v\?\([^[:space:]]*\).*@\1@p' \
               | tail -n 1 \
               | tr -d '\r\n')"
    fi

    if [ -z "$tag" ]; then
        die "Could not resolve latest version from $url. Set VELLAVETO_VERSION to pin one." 3
    fi
    echo "$tag"
}

# ──────────────────────── binary selection ────────────────────────────────

select_binaries() {
    if [ -z "${VELLAVETO_BINARY:-}" ]; then
        echo "$ALL_BINARIES"
        return
    fi

    # Validate the chosen binary against the known list to catch typos
    # before we hit a tar-extract failure.
    for b in $ALL_BINARIES; do
        if [ "$b" = "$VELLAVETO_BINARY" ]; then
            echo "$VELLAVETO_BINARY"
            return
        fi
    done
    die "Unknown VELLAVETO_BINARY: $VELLAVETO_BINARY
   Valid: $ALL_BINARIES" 1
}

# ─────────────────────── install dir handling ─────────────────────────────

prepare_install_dir() {
    dir="${VELLAVETO_INSTALL_DIR:-$HOME/.local/bin}"
    if ! mkdir -p "$dir" 2>/dev/null; then
        die "Cannot create install directory: $dir
   Override with VELLAVETO_INSTALL_DIR=/some/writable/path" 1
    fi
    if [ ! -w "$dir" ]; then
        die "Install directory is not writable: $dir
   Override with VELLAVETO_INSTALL_DIR=/some/writable/path" 1
    fi
    echo "$dir"
}

# ─────────────────── existing-install conflict check ──────────────────────

plan_install() {
    install_dir="$1"
    binaries="$2"
    version="$3"

    # Partition the requested binaries into three buckets:
    #   to_install — not present, will be written fresh (no prompt)
    #   conflicts  — present at a different version, needs confirmation
    #   (silent)   — present at the target version, skipped
    to_install=""
    conflicts=""
    for b in $binaries; do
        existing="$install_dir/$b"
        if [ ! -x "$existing" ]; then
            to_install="$to_install $b"
            continue
        fi
        if cur="$("$existing" --version 2>/dev/null | head -n1)" \
           && echo "$cur" | grep -qF "$version"; then
            log "$b $version already installed at $existing — skipping"
            continue
        fi
        conflicts="$conflicts $b"
    done

    # shellcheck disable=SC2086
    set -- $conflicts
    if [ $# -gt 0 ]; then
        if [ "${VELLAVETO_FORCE:-0}" = "1" ]; then
            warn "Overwriting existing binaries: $*"
        elif [ ! -t 0 ]; then
            die "Refusing to overwrite existing binaries without confirmation:
$(for c in "$@"; do echo "     $install_dir/$c"; done)
   Re-run with VELLAVETO_FORCE=1 to overwrite." 1
        else
            warn "Found existing binaries in $install_dir:"
            for c in "$@"; do printf '     %s\n' "$c" >&2; done
            printf '%s?%s Overwrite? [y/N] ' "$C_YELLOW" "$C_RESET" >&2
            read -r reply
            case "$reply" in
                y|Y|yes|YES) ;;
                *) die "Aborted by user." 1 ;;
            esac
        fi
        to_install="$to_install $conflicts"
    fi

    # Trim leading whitespace so callers can do `[ -z "$result" ]` for the empty case.
    echo "$to_install" | sed 's/^ *//'
}

# ─────────────────────────── main install ─────────────────────────────────

main() {
    target="$(detect_target)"
    version="$(resolve_version)"
    binaries="$(select_binaries)"
    install_dir="$(prepare_install_dir)"

    log "Vellaveto installer"
    log "  version : ${C_BOLD}${version}${C_RESET}"
    log "  target  : ${target}"
    log "  install : ${install_dir}"
    log "  binaries: $(echo "$binaries" | tr '\n' ' ')"

    # Decide which binaries actually need writing, prompting on overwrites.
    needs_install="$(plan_install "$install_dir" "$binaries" "$version")"
    if [ -z "$needs_install" ]; then
        log "Everything is up to date. Nothing to do."
        print_next_steps "$install_dir" "$binaries"
        return 0
    fi

    archive="vellaveto-${version}-${target}.tar.gz"
    base_url="https://github.com/$REPO/releases/download/v${version}"

    # Use a unique, auto-cleaned temp directory so partial downloads can't poison
    # a future run and so we never leave files behind on error.
    tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t vellaveto)"
    trap 'rm -rf "$tmpdir"' EXIT INT TERM

    log "Downloading $archive"
    fetch_file "$base_url/$archive" "$tmpdir/$archive" \
        || die "Download failed: $base_url/$archive" 3

    log "Verifying SHA-256 checksum"
    fetch_file "$base_url/checksums-sha256.txt" "$tmpdir/checksums.txt" \
        || die "Could not download checksums-sha256.txt" 3

    expected="$(grep -F "  $archive" "$tmpdir/checksums.txt" | awk '{print $1}' | head -n1)"
    if [ -z "$expected" ]; then
        die "No checksum for $archive in checksums-sha256.txt" 4
    fi
    actual="$(cd "$tmpdir" && $SHA256 "$archive" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        rm -f "$tmpdir/$archive"
        die "Checksum mismatch for $archive
   expected: $expected
   actual  : $actual
   The download was corrupted or tampered with — refusing to install." 4
    fi

    log "Extracting"
    mkdir -p "$tmpdir/extracted"
    tar -xzf "$tmpdir/$archive" -C "$tmpdir/extracted" \
        || die "Failed to extract $archive" 1

    log "Installing to $install_dir"
    for b in $needs_install; do
        src="$tmpdir/extracted/$b"
        if [ ! -f "$src" ]; then
            die "Binary missing from archive: $b" 1
        fi
        # Install via temp + mv so an in-use binary on Linux is replaced atomically.
        cp "$src" "$install_dir/$b.new"
        chmod +x "$install_dir/$b.new"
        mv "$install_dir/$b.new" "$install_dir/$b"
        log "  installed ${C_BOLD}${b}${C_RESET}"
    done

    print_next_steps "$install_dir" "$binaries"
}

# ─────────────────────────── post-install ─────────────────────────────────

print_next_steps() {
    install_dir="$1"
    binaries="$2"

    printf '\n'
    printf '%s✓ Vellaveto installed.%s\n\n' "$C_BOLD$C_GREEN" "$C_RESET"

    # Only nag about PATH if the user's shell can't actually find the binaries —
    # otherwise the message is just noise on the happy path.
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *)
            printf '%s%s is not on your PATH.%s Add it to your shell profile:\n' \
                "$C_YELLOW" "$install_dir" "$C_RESET"
            printf '\n'
            # shellcheck disable=SC2016  # $PATH is a literal for the user to copy
            printf '  %sexport PATH="%s:$PATH"%s\n' "$C_BOLD" "$install_dir" "$C_RESET"
            printf '\n'
            ;;
    esac

    printf '%sNext steps:%s\n' "$C_BOLD" "$C_RESET"

    # Tailor the suggestion to what we actually installed so we don't tell users
    # to run a binary that isn't on disk.
    case " $binaries " in
        *" vellaveto-proxy "*)
            printf '\n'
            printf '  %s# Protect an MCP server with a built-in policy preset%s\n' "$C_DIM" "$C_RESET"
            printf '  vellaveto-proxy --protect shield -- ./your-mcp-server\n'
            ;;
    esac

    case " $binaries " in
        *" vellaveto-shield "*)
            printf '\n'
            printf '  %s# Run the consumer privacy shield%s\n' "$C_DIM" "$C_RESET"
            printf '  vellaveto-shield --help\n'
            ;;
    esac

    case " $binaries " in
        *" vellaveto "*)
            printf '\n'
            printf '  %s# Start the HTTP policy server%s\n' "$C_DIM" "$C_RESET"
            printf '  vellaveto serve --config examples/presets/shield.toml\n'
            ;;
    esac

    printf '\n'
    printf 'Docs: %shttps://github.com/%s%s\n' "$C_BOLD" "$REPO" "$C_RESET"
    printf '\n'
}

main "$@"
