# db_brute

Service credential checker for authorized security testing. Supports databases, SSH, and Apache Tomcat Manager.

## Supported Services

| Service                | Default Port | Driver/Protocol |
|------------------------|--------------|-----------------|
| MySQL                  | 3306         | pymysql         |
| MSSQL                  | 1433         | pymssql         |
| PostgreSQL             | 5432         | psycopg2        |
| SSH                    | 22           | paramiko        |
| Apache Tomcat Manager  | 8080         | HTTP Basic      |

## Installation

### Ubuntu/Debian
```bash
sudo apt install python3-pymssql python3-pymysql python3-psycopg2 python3-paramiko
```

### pip
```bash
pip3 install pymssql pymysql psycopg2-binary paramiko
```

## Usage

```bash
# Single target
python3 db_brute.py --service mysql -t 192.168.1.100
python3 db_brute.py --service postgres -t 10.0.0.50 -p 5433

# Multiple targets from file
python3 db_brute.py --service mssql -T targets.txt

# Custom credentials and output
python3 db_brute.py --service mysql -t 192.168.1.100 -c custom_creds.txt -o results.txt

# Tomcat Manager over HTTP or HTTPS
python3 db_brute.py --service tomcat -t 192.168.1.100
python3 db_brute.py --service tomcat -t 192.168.1.100 -p 8443 --ssl
python3 db_brute.py --service tomcat -t 192.168.1.100 --uri /custom/manager
python3 db_brute.py --service tomcat -T tomcat-urls.txt
```

If you omit `-c/--creds`, the tool uses `credz/<service>.txt`. The
`credz/tomcat.txt` defaults are a deduplicated snapshot of Metasploit's Tomcat
Manager username, password, and explicit username/password lists, augmented
with non-overlapping curated defaults from Nuclei Templates, SecLists, and
Nmap.

The snapshot is generated from Metasploit Framework revision
`54152b2f90a1ae66ff6b2cd90704ee8cdba97126` using:

- `data/wordlists/tomcat_mgr_default_users.txt`
- `data/wordlists/tomcat_mgr_default_pass.txt`
- `data/wordlists/tomcat_mgr_default_userpass.txt`

`--db` and `-d` remain available as aliases for `--service`.

## Options

```
--service, --db, -d
                  Service type: mssql, mysql, postgres, ssh, tomcat (required)
-t, --target      Single target (host, host:port, or URL)
-T, --target-file File containing targets (one per line)
-p, --port        Port override (default: service-specific)
-c, --creds       Credential file (default: credz/<service>.txt)
--threads         Concurrent threads (default: 1)
--timeout         Connection timeout in seconds (default: 5)
-o, --output      Output file for valid creds (default: ./valid_credz.txt)
-l, --log         Log file for all attempts
--delay           Delay between attempts per thread (default: 0)
--ssl             Use HTTPS for scheme-less targets without certificate checks
--uri             Service URI override (for example: /manager/html)
```

## File Formats

### Targets file
```
192.168.1.100
192.168.1.101:3307
db.example.com
https://192.168.1.102:8443
http://192.168.1.103:8080
```

Tomcat target files may mix `http://` and `https://` base URLs. The URL scheme
is applied per target and takes precedence over `--ssl`. URLs without explicit
ports use 80 for HTTP and 443 for HTTPS. Use `--uri` to change the default
`/manager/html` path for all Tomcat targets. HTTPS certificate verification is
disabled to support internal services using self-signed certificates.

Before scheduling credentials, the Tomcat driver requires each target to
return an HTTP 401 Tomcat Basic-authentication challenge. Redirects and other
responses are skipped with a diagnostic; specify the redirected URL explicitly
if it is an in-scope Tomcat Manager endpoint.

### Credentials file
```
username:password
sa:password123
admin:admin
```
