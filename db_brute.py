#!/usr/bin/env python3
"""
Database credential checker - supports multiple database types.
For authorized security testing only.
"""

import sys
import argparse
import shutil
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from drivers import get_driver, list_drivers, HostUnreachable


class Status:
    """Thread-safe status tracker with terminal output."""

    def __init__(self, total: int, output_file: Path, log_file: Path = None):
        self.total = total
        self.completed = 0
        self.valid_count = 0
        self.output_file = output_file
        self.log_file = log_file
        self.lock = Lock()
        self.unreachable_hosts = set()

    def update(self, host: str, port: int, username: str, password: str, success: bool):
        with self.lock:
            self.completed += 1
            target = f"{host}:{port}"

            if self.log_file:
                status_str = "SUCCESS" if success else "FAILED"
                with open(self.log_file, 'a') as f:
                    f.write(f"{status_str} {target} {username}:{password}\n")

            if success:
                self.valid_count += 1
                with open(self.output_file, 'a') as f:
                    f.write(f"{host}:{port}:{username}:{password}\n")
                sys.stdout.write(f"\r\033[K[+] VALID: {target} - {username}:{password}\n")

            self._draw_status(target, username, password)

    def skip(self, host: str, port: int, username: str, password: str, reason: str = "unreachable"):
        with self.lock:
            self.completed += 1
            target = f"{host}:{port}"

            if self.log_file:
                with open(self.log_file, 'a') as f:
                    f.write(f"SKIPPED {target} {username}:{password} {reason}\n")

            self._draw_status(target, username, password)

    def mark_unreachable(self, host: str, port: int, reason: str) -> bool:
        with self.lock:
            target = f"{host}:{port}"
            if target in self.unreachable_hosts:
                return False
            self.unreachable_hosts.add(target)
            sys.stdout.write(f"\n[!] Marking {target} as unreachable: {reason}\n")
            sys.stdout.flush()
            return True

    def is_unreachable(self, host: str, port: int) -> bool:
        with self.lock:
            return f"{host}:{port}" in self.unreachable_hosts

    def set_current(self, host: str, port: int, username: str, password: str):
        with self.lock:
            self._draw_status(f"{host}:{port}", username, password)

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


def test_credential(driver, host: str, port: int, username: str, password: str,
                    timeout: int, status: Status, delay: float = 0, host_lock: Lock = None) -> bool:
    """Test a single credential against a target."""
    lock = host_lock if host_lock is not None else Lock()
    with lock:
        if delay > 0:
            time.sleep(delay)
        if status.is_unreachable(host, port):
            status.skip(host, port, username, password)
            return False
        status.set_current(host, port, username, password)
        try:
            success = driver.connect(host, port, username, password, timeout)
        except HostUnreachable as exc:
            status.mark_unreachable(host, port, str(exc))
            status.skip(host, port, username, password, str(exc))
            return False
        status.update(host, port, username, password, success)
        return success


def parse_credential_file(filepath: Path) -> list[tuple[str, str]]:
    """Parse a credential file with username:password format."""
    credentials = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                username, password = line.split(':', 1)
                credentials.append((username, password))
    return credentials


def parse_targets(target: str, target_file: Path, default_port: int, port_override: int = None) -> list[tuple[str, int]]:
    """
    Parse targets from either a single target string or a file.
    Returns list of (host, port) tuples.
    If port_override is set, it takes precedence over any port in the target.
    """
    targets = []

    if target:
        if port_override:
            host = target.rsplit(':', 1)[0] if ':' in target else target
            targets.append((host, port_override))
        elif ':' in target:
            host, port = target.rsplit(':', 1)
            targets.append((host, int(port)))
        else:
            targets.append((target, default_port))

    if target_file:
        with open(target_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if port_override:
                    host = line.rsplit(':', 1)[0] if ':' in line else line
                    targets.append((host, port_override))
                elif ':' in line:
                    host, port = line.rsplit(':', 1)
                    targets.append((host, int(port)))
                else:
                    targets.append((line, default_port))

    return targets


def get_default_cred_file(db_type: str) -> Path:
    """Get default credential file path for a database type."""
    script_dir = Path(__file__).resolve().parent
    return script_dir / 'credz' / f'{db_type}.txt'


def main():
    available_dbs = list_drivers()

    parser = argparse.ArgumentParser(
        description='Database credential checker for authorized security testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --db mysql -t 192.168.1.100
  %(prog)s --db mssql -t 10.0.0.50 -p 1434 --threads 20
  %(prog)s --db mysql -T targets.txt -c custom_creds.txt -o results.txt
        '''
    )

    parser.add_argument('--db', '-d', required=True, choices=available_dbs,
                        help=f'Database type: {", ".join(available_dbs)}')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target (host or host:port)')
    target_group.add_argument('-T', '--target-file', type=Path,
                              help='File containing targets (host:port per line)')

    parser.add_argument('-p', '--port', type=int, default=None,
                        help='Port override (default: DB-specific)')
    parser.add_argument('-c', '--creds', type=Path, default=None,
                        help='Credential file (default: credz/<db>.txt)')
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

    args = parser.parse_args()

    # Get driver
    driver = get_driver(args.db)

    # Set credential file
    cred_file = args.creds if args.creds else get_default_cred_file(args.db)

    if not cred_file.exists():
        print(f"[!] Credential file not found: {cred_file}", file=sys.stderr)
        sys.exit(1)

    if args.target_file and not args.target_file.exists():
        print(f"[!] Target file not found: {args.target_file}", file=sys.stderr)
        sys.exit(1)

    targets = parse_targets(args.target, args.target_file, driver.default_port, args.port)
    credentials = parse_credential_file(cred_file)

    if not targets:
        print("[!] No targets specified", file=sys.stderr)
        sys.exit(1)

    if not credentials:
        print("[!] No credentials found in file", file=sys.stderr)
        sys.exit(1)

    total_checks = len(targets) * len(credentials)

    print(f"[*] Database: {driver.name.upper()}")
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
            for host, port in targets:
                future = executor.submit(
                    test_credential,
                    driver,
                    host,
                    port,
                    username,
                    password,
                    args.timeout,
                    status,
                    args.delay,
                    host_locks[(host, port)]
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
