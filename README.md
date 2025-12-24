# db_brute

Database credential checker for authorized security testing. Supports multiple database types.

## Supported Databases

| Database   | Default Port | Driver     |
|------------|--------------|------------|
| MySQL      | 3306         | pymysql    |
| MSSQL      | 1433         | pymssql    |
| PostgreSQL | 5432         | psycopg2   |
| SSH        | 22           | paramiko   |

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
python3 db_brute.py --db mysql -t 192.168.1.100
python3 db_brute.py --db postgres -t 10.0.0.50 -p 5433

# Multiple targets from file
python3 db_brute.py --db mssql -T targets.txt

# Custom credentials and output
python3 db_brute.py --db mysql -t 192.168.1.100 -c custom_creds.txt -o results.txt
```

## Options

```
--db, -d          Database type: mssql, mysql, postgres, ssh (required)
-t, --target      Single target (host or host:port)
-T, --target-file File containing targets (one per line)
-p, --port        Port override (default: DB-specific)
-c, --creds       Credential file (default: credz/<db>.txt)
--threads         Concurrent threads (default: 1)
--timeout         Connection timeout in seconds (default: 5)
-o, --output      Output file for valid creds (default: ./valid_credz.txt)
-l, --log         Log file for all attempts
--delay           Delay between attempts per thread (default: 0)
```

## File Formats

### Targets file
```
192.168.1.100
192.168.1.101:3307
db.example.com
```

### Credentials file
```
username:password
sa:password123
admin:admin
```
