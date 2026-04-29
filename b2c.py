#!/usr/bin/env python3
"""
burp2curl — Convert Burp Suite intercepted requests to curl commands

Usage:
  burp2curl                        interactive paste mode (Ctrl+D to finish)
  burp2curl request.txt            read from file
  cat request.txt | burp2curl      pipe from stdin
  burp2curl -s http request.txt    force HTTP scheme
  burp2curl -k request.txt         add -k (skip SSL verify)
  burp2curl --proxy request.txt    route through Burp proxy (127.0.0.1:8080)
  burp2curl --one-line request.txt output as single line (no backslashes)
"""

import sys
import os
import argparse
import shlex
from textwrap import indent


# ─── Headers to drop (curl or the server handles these automatically) ──────────
DROP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade-insecure-requests",  # browser-only hint
}


# ─── Parser ────────────────────────────────────────────────────────────────────

def parse_raw_request(raw: str):
    """
    Parse a raw HTTP/1.x request string (Burp format) into its components.
    Returns: (method, path, http_version, headers_dict, body_str)
    """
    # Normalise line endings
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")

    # Skip leading blank lines (common when pasting)
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1

    if i >= len(lines):
        raise ValueError("Request is empty.")

    # ── Request line ──────────────────────────────────────────────────────────
    request_line = lines[i].strip()
    i += 1
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"Unrecognised request line: {request_line!r}")

    method = parts[0].upper()
    path   = parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    # ── Headers ───────────────────────────────────────────────────────────────
    headers = {}        # preserves insertion order (Python 3.7+)
    header_order = []   # keep original casing for display

    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():   # blank line = end of headers
            break
        if ":" in line:
            key, _, value = line.partition(":")
            key   = key.strip()
            value = value.strip()
            headers[key.lower()] = (key, value)   # lower-key → (original-key, value)
            header_order.append(key.lower())

    # ── Body ──────────────────────────────────────────────────────────────────
    body = "\n".join(lines[i:]).rstrip("\n")

    return method, path, http_version, headers, header_order, body


# ─── Builder ───────────────────────────────────────────────────────────────────

def build_curl(
    method, path, headers, header_order, body,
    scheme="https",
    insecure=False,
    proxy=None,
    separate_cookies=False,
    follow_redirects=False,
    verbose=False,
    one_line=False,
):
    host_entry = headers.get("host")
    if not host_entry:
        raise ValueError("No Host header found in request.")
    host = host_entry[1]

    # If path is already a full URL (e.g. absolute-form proxy requests)
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"

    flags = ["curl"]

    # ── Optional flags ────────────────────────────────────────────────────────
    if verbose:
        flags.append("-v")
    if insecure:
        flags.append("-k")
    if follow_redirects:
        flags.append("-L")
    if proxy:
        flags.append(f"--proxy {shlex.quote(proxy)}")

    # ── Method ────────────────────────────────────────────────────────────────
    if method != "GET":
        flags.append(f"-X {method}")

    # ── URL ───────────────────────────────────────────────────────────────────
    flags.append(shlex.quote(url))

    # ── Headers ───────────────────────────────────────────────────────────────
    cookies = None
    compressed = False

    for key_lower in header_order:
        if key_lower in DROP_HEADERS:
            continue
        original_key, value = headers[key_lower]

        if key_lower == "accept-encoding" and "gzip" in value.lower():
            compressed = True
            continue   # curl handles this with --compressed

        if separate_cookies and key_lower == "cookie":
            cookies = value
            continue   # handled separately below

        flags.append(f"-H {shlex.quote(f'{original_key}: {value}')}")

    if compressed:
        flags.append("--compressed")

    if cookies:
        flags.append(f"-b {shlex.quote(cookies)}")

    # ── Body ──────────────────────────────────────────────────────────────────
    if body:
        # Use --data-binary to preserve newlines exactly (important for JSON/XML)
        flags.append(f"--data-binary {shlex.quote(body)}")

    # ── Format ────────────────────────────────────────────────────────────────
    if one_line:
        return " ".join(flags)
    else:
        return " \\\n  ".join(flags)


# ─── Presentation ──────────────────────────────────────────────────────────────

BANNER = """\033[1;36m
  ██████╗ ██╗   ██╗██████╗ ██████╗      ██████╗ ██╗   ██╗██████╗ ██╗
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗    ██╔════╝ ██║   ██║██╔══██╗██║
  ██████╔╝██║   ██║██████╔╝██████╔╝    ██║      ██║   ██║██████╔╝██║
  ██╔══██╗██║   ██║██╔══██╗██╔═══╝     ██║      ██║   ██║██╔══██╗██║
  ██████╔╝╚██████╔╝██║  ██║██║         ╚██████╗ ╚██████╔╝██║  ██║███████╗
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝
\033[0m\033[2m  Burp Suite → curl  |  paste your request, get a curl command\033[0m
"""

def print_banner():
    print(BANNER, file=sys.stderr)

def dim(s):    return f"\033[2m{s}\033[0m"
def green(s):  return f"\033[1;32m{s}\033[0m"
def yellow(s): return f"\033[1;33m{s}\033[0m"
def cyan(s):   return f"\033[1;36m{s}\033[0m"
def red(s):    return f"\033[1;31m{s}\033[0m"

def print_summary(method, path, headers, body, scheme):
    host = headers.get("host", ("Host", "?"))[1]
    ct   = headers.get("content-type", ("", ""))[1]
    clen = len(body.encode()) if body else 0
    print(dim("─" * 60), file=sys.stderr)
    print(f"  {cyan('METHOD')}   {yellow(method)}", file=sys.stderr)
    print(f"  {cyan('URL')}      {scheme}://{host}{path}", file=sys.stderr)
    if ct:
        print(f"  {cyan('BODY')}     {ct} ({clen} bytes)", file=sys.stderr)
    print(dim("─" * 60), file=sys.stderr)


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="burp2curl",
        description="Convert a raw Burp Suite HTTP request to a curl command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  burp2curl                        paste mode — type/paste request, Ctrl+D to finish
  burp2curl req.txt                read request from file
  cat req.txt | burp2curl          pipe from stdin
  burp2curl -s http req.txt        force http:// scheme
  burp2curl -k req.txt             add -k (skip TLS verification)
  burp2curl --proxy req.txt        route through Burp at 127.0.0.1:8080
  burp2curl -c req.txt             put cookies in -b flag instead of -H
  burp2curl --one-line req.txt     single-line output (no backslash continuation)
        """
    )

    parser.add_argument(
        "file", nargs="?",
        help="path to file containing the raw request (omit to paste or pipe)"
    )
    parser.add_argument(
        "-s", "--scheme", choices=["http", "https"], default="https",
        metavar="SCHEME",
        help="URL scheme to use: http or https (default: https)"
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="add -k flag to skip TLS certificate verification"
    )
    parser.add_argument(
        "--proxy", nargs="?", const="http://127.0.0.1:8080",
        metavar="URL",
        help="route through proxy (default: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-c", "--cookies", action="store_true",
        help="put cookies in -b flag instead of -H Cookie"
    )
    parser.add_argument(
        "-L", "--follow-redirects", action="store_true",
        help="add -L flag to follow redirects"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="add -v flag to curl output"
    )
    parser.add_argument(
        "--one-line", action="store_true",
        help="output as a single line (no \\ line continuation)"
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="suppress the ASCII banner"
    )

    args = parser.parse_args()

    # ── Print banner unless suppressed or piped ────────────────────────────────
    is_tty = sys.stderr.isatty()
    if not args.no_banner and is_tty:
        print_banner()

    # ── Read raw request ───────────────────────────────────────────────────────
    try:
        if args.file:
            if not os.path.isfile(args.file):
                print(red(f"[!] File not found: {args.file}"), file=sys.stderr)
                sys.exit(1)
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            if is_tty:
                print(dim(f"  reading from {args.file}…"), file=sys.stderr)

        elif not sys.stdin.isatty():
            # Piped input
            raw = sys.stdin.read()

        else:
            # Interactive paste mode
            print(
                dim("  Paste your Burp request below.\n"
                    "  Press ") +
                yellow("Ctrl+D") +
                dim(" (Linux/macOS) or ") +
                yellow("Ctrl+Z → Enter") +
                dim(" (Windows) when done.\n"),
                file=sys.stderr
            )
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            raw = "\n".join(lines)

    except KeyboardInterrupt:
        print(red("\n[!] Cancelled."), file=sys.stderr)
        sys.exit(1)

    # ── Parse ──────────────────────────────────────────────────────────────────
    try:
        method, path, http_version, headers, header_order, body = parse_raw_request(raw)
    except ValueError as e:
        print(red(f"[!] Parse error: {e}"), file=sys.stderr)
        sys.exit(1)

    if is_tty:
        print_summary(method, path, headers, body, args.scheme)

    # ── Build curl command ─────────────────────────────────────────────────────
    try:
        curl_cmd = build_curl(
            method=method,
            path=path,
            headers=headers,
            header_order=header_order,
            body=body,
            scheme=args.scheme,
            insecure=args.insecure,
            proxy=args.proxy,
            separate_cookies=args.cookies,
            follow_redirects=args.follow_redirects,
            verbose=args.verbose,
            one_line=args.one_line,
        )
    except ValueError as e:
        print(red(f"[!] Build error: {e}"), file=sys.stderr)
        sys.exit(1)

    # ── Output ─────────────────────────────────────────────────────────────────
    if is_tty:
        print(file=sys.stderr)
        print(green("  ✓ curl command:"), file=sys.stderr)
        print(dim("─" * 60), file=sys.stderr)

    print(curl_cmd)

    if is_tty:
        print(dim("─" * 60), file=sys.stderr)


if __name__ == "__main__":
    main()
