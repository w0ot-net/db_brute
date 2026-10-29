#!/usr/bin/env python3
"""
Service credential checker - supports multiple network service types.
For authorized security testing only.
"""

import sys
import argparse
import shutil
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Optional
from urllib.parse import urlsplit

from drivers import (
    get_driver,
    list_drivers,
    HostUnreachable,
    Target,
    TargetRejected,
)


class Status:
    """Thread-safe status tracker with terminal output."""

    def __init__(self, total: int, output_file: Path, log_file: Path = None):
        self.total = total
        self.completed = 0
        self.valid_count = 0
        self.output_file = output_file
        self.log_file = log_file
        self.lock = Lock()
        self.unreachable_targets = set()

    def update(
        self,
        target: Target,
        username: str,
        password: str,
        success: bool,
    ):
        with self.lock:
            self.completed += 1
            target_name = target.display()

            if self.log_file:
                status_str = "SUCCESS" if success else "FAILED"
                with open(self.log_file, 'a') as f:
                    f.write(f"{status_str} {target_name} {username}:{password}\n")

            if success:
                self.valid_count += 1
                with open(self.output_file, 'a') as f:
                    f.write(f"{target_name}:{username}:{password}\n")
                sys.stdout.write(
                    f"\r\033[K[+] VALID: {target_name} - {username}:{password}\n"
                )

            self._draw_status(target_name, username, password)

    def skip(
        self,
        target: Target,
        username: str,
        password: str,
        reason: str = "unreachable",
    ):
        with self.lock:
            self.completed += 1
            target_name = target.display()

            if self.log_file:
                with open(self.log_file, 'a') as f:
                    f.write(
                        f"SKIPPED {target_name} {username}:{password} {reason}\n"
                    )

            self._draw_status(target_name, username, password)

    def mark_unreachable(self, target: Target, reason: str) -> bool:
        with self.lock:
            if target in self.unreachable_targets:
                return False
            self.unreachable_targets.add(target)
            sys.stdout.write(
                f"\n[!] Marking {target.display()} as unreachable: {reason}\n"
            )
            sys.stdout.flush()
            return True

    def is_unreachable(self, target: Target) -> bool:
        with self.lock:
            return target in self.unreachable_targets

    def set_current(self, target: Target, username: str, password: str):
        with self.lock:
            self._draw_status(target.display(), username, password)

    def _draw_status(self, target: str, username: str, password: str):
        pct = (self.completed / self.total) * 100 if self.total > 0 else 0
        status = f"[{self.completed}/{self.total} ({pct:.1f}%)] Valid: {self.valid_count} | Testing: {target} - {username}:{password}"
        cols = shutil.get_terminal_size((80, 24)).columns
        if len(status) > cols:
            status = status[:cols-3] + "..."
        sys.stdout.write(f"\r\033[K{status}")
        sys.stdout.flush()

    def finish(self):
        with self.lock:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


def test_credential(
    driver,
    target: Target,
    username: str,
    password: str,
    timeout: int,
    status: Status,
    delay: float = 0,
    host_lock: Lock = None,
) -> bool:
    """Test a single credential against a target."""
    lock = host_lock if host_lock is not None else Lock()
    with lock:
        if delay > 0:
            time.sleep(delay)
        if status.is_unreachable(target):
            status.skip(target, username, password)
            return False
        status.set_current(target, username, password)
        try:
            success = driver.connect_target(target, username, password, timeout)
        except HostUnreachable as exc:
            status.mark_unreachable(target, str(exc))
            status.skip(target, username, password, str(exc))
            return False
        status.update(target, username, password, success)
        return success


def preflight_target(
    driver,
    target: Target,
    timeout: int,
) -> tuple[Optional[Target], Optional[str]]:
    """Check whether a target is suitable for the selected credential driver."""
    try:
        return driver.preflight_target(target, timeout), None
    except HostUnreachable as exc:
        return None, f"unreachable: {exc}"
    except TargetRejected as exc:
        return None, str(exc)


def preflight_targets(
    driver,
    targets: list[Target],
    timeout: int,
    threads: int,
) -> list[Target]:
    """Filter targets through service-specific checks before scheduling logins."""
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(
            executor.map(
                lambda target: preflight_target(driver, target, timeout),
                targets,
            )
        )

    eligible_targets = []
    seen_targets = set()
    for original_target, (resolved_target, reason) in zip(targets, results):
        if resolved_target is not None:
            if resolved_target not in seen_targets:
                eligible_targets.append(resolved_target)
                seen_targets.add(resolved_target)
            continue
        print(f"[!] Skipping {original_target.display()}: {reason}")
    return eligible_targets


def parse_credential_file(filepath: Path) -> list[tuple[str, str]]:
    """Parse a credential file with username:password format."""
    credentials = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                username, password = line.split(':', 1)
                credentials.append((username, password))
            else:
                print(f"[!] Skipping invalid credential line {line_num} in {filepath}: missing ':'", file=sys.stderr)
    return credentials


def parse_target(
    value: str,
    default_port: int,
    port_override: Optional[int] = None,
) -> Target:
    """Parse a URL, host:port pair, or bare host into a target."""
    if "://" in value:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported URL scheme in target: {value}")
        if not parsed.hostname:
            raise ValueError(f"URL target is missing a hostname: {value}")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(f"URL target must not contain credentials: {value}")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError(
                f"URL target must be a base URL without a path, query, or fragment: {value}"
            )
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid port in target: {value}") from exc
        if port_override is not None:
            port = port_override
        else:
            port = parsed_port or (443 if scheme == "https" else 80)
        return Target(parsed.hostname, port, scheme)

    if port_override is not None:
        host = value.rsplit(":", 1)[0] if ":" in value else value
        return Target(host, port_override)
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"invalid port in target: {value}") from exc
        return Target(host, port)
    return Target(value, default_port)


def parse_targets(
    target: Optional[str],
    target_file: Optional[Path],
    default_port: int,
    port_override: Optional[int] = None,
) -> list[Target]:
    """Parse targets from a single value or a file."""
    targets = []

    if target:
        targets.append(parse_target(target, default_port, port_override))

    if target_file:
        with open(target_file, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                try:
                    targets.append(
                        parse_target(value, default_port, port_override)
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"{target_file}:{line_number}: {exc}"
                    ) from exc

    return targets


def get_default_cred_file(service: str) -> Path:
    """Get the default credential file path for a service."""
    script_dir = Path(__file__).resolve().parent
    return script_dir / 'credz' / f'{service}.txt'


def build_parser(available_services: list[str]) -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description='Service credential checker for authorized security testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --service mysql -t 192.168.1.100
  %(prog)s --service mssql -t 10.0.0.50 -p 1434 --threads 20
  %(prog)s --service tomcat -t 10.0.0.80
  %(prog)s --service tomcat -t 10.0.0.80 -p 8443 --ssl
        '''
    )

    parser.add_argument('--service', '--db', '-d', dest='service', required=True,
                        choices=available_services,
                        help=f'Service type: {", ".join(available_services)}')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '-t', '--target', help='Single target (host, host:port, or URL)'
    )
    target_group.add_argument('-T', '--target-file', type=Path,
                              help='File containing targets (one per line)')

    parser.add_argument('-p', '--port', type=int, default=None,
                        help='Port override (default: service-specific)')
    parser.add_argument('-c', '--creds', type=Path, default=None,
                        help='Credential file (default: credz/<service>.txt)')
    parser.add_argument('--threads', type=int, default=1,
                        help='Number of concurrent threads (default: 1)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Connection timeout in seconds (default: 5)')
    parser.add_argument('-o', '--output', type=Path, default=Path('./valid_credz.txt'),
                        help='Output file for valid credentials (default: ./valid_credz.txt)')
    parser.add_argument('-l', '--log', type=Path, default=None,
                        help='Log file for all attempts (optional)')
    parser.add_argument('--delay', type=float, default=0,
                        help='Delay in seconds between attempts per thread (default: 0)')
    parser.add_argument('--ssl', action='store_true',
                        help='Use HTTPS for scheme-less targets (no certificate verification)')
    parser.add_argument('--uri', default=None,
                        help='Service URI override (for example: /manager/html)')

    return parser


def main():
    parser = build_parser(list_drivers())

    args = parser.parse_args()

    # Get driver
    driver = get_driver(args.service)
    try:
        driver.configure(use_ssl=args.ssl, uri=args.uri)
    except ValueError as exc:
        parser.error(str(exc))

    # Set credential file
    cred_file = args.creds if args.creds else get_default_cred_file(args.service)

    if not cred_file.exists():
        print(f"[!] Credential file not found: {cred_file}", file=sys.stderr)
        sys.exit(1)

    if args.target_file and not args.target_file.exists():
        print(f"[!] Target file not found: {args.target_file}", file=sys.stderr)
        sys.exit(1)

    try:
        targets = parse_targets(
            args.target, args.target_file, driver.default_port, args.port
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if any(target.scheme for target in targets) and not driver.supports_url_targets:
        parser.error(f"{driver.name} does not support URL targets")

    credentials = parse_credential_file(cred_file)

    if not targets:
        print("[!] No targets specified", file=sys.stderr)
        sys.exit(1)

    if not credentials:
        print("[!] No credentials found in file", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Service: {driver.name.upper()}")
    targets = preflight_targets(
        driver,
        targets,
        timeout=args.timeout,
        threads=args.threads,
    )
    if not targets:
        print("[!] No targets passed service preflight", file=sys.stderr)
        sys.exit(1)

    total_checks = len(targets) * len(credentials)

    print(f"[*] Targets: {len(targets)} | Credentials: {len(credentials)} ({cred_file.name}) | Total: {total_checks}")
    print(f"[*] Threads: {args.threads} | Output: {args.output}", end="")
    if args.log:
        print(f" | Log: {args.log}")
    else:
        print()
    print("-" * 60)

    status = Status(total_checks, args.output, args.log)

    host_locks = {target: Lock() for target in targets}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for username, password in credentials:
            for target in targets:
                future = executor.submit(
                    test_credential,
                    driver,
                    target,
                    username,
                    password,
                    args.timeout,
                    status,
                    args.delay,
                    host_locks[target],
                )
                futures.append(future)

        for future in as_completed(futures):
            future.result()

    status.finish()
    print("-" * 60)
    print(f"[*] Complete: {status.valid_count}/{total_checks} valid credentials found")

    if status.valid_count > 0:
        print(f"[*] Valid credentials saved to: {args.output}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
