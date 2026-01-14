#!/usr/bin/env python3
"""Backup MySQL database using environment variables provided by Railway.

Usage: railway run python scripts/backup_mysql.py

Creates a gzip-compressed SQL dump file: backup-YYYYmmdd-HHMMSS.sql.gz
This script: exports CREATE TABLE statements and INSERTs for data.
"""

import os
import sys
import gzip
import datetime
import pymysql
from pymysql.converters import escape_string


def get_conn():
    host = os.environ.get("MYSQLHOST") or os.environ.get("MYSQL_HOST") or os.environ.get("MYSQL_PUBLIC_URL")
    port = int(os.environ.get("MYSQLPORT") or os.environ.get("MYSQL_PORT") or 3306)
    user = os.environ.get("MYSQLUSER") or os.environ.get("MYSQL_USER") or os.environ.get("MYSQL_USER")
    password = os.environ.get("MYSQLPASSWORD") or os.environ.get("MYSQL_PASSWORD") or os.environ.get("MYSQLROOTPASSWORD")
    db = os.environ.get("MYSQLDATABASE") or os.environ.get("MYSQL_DATABASE") or os.environ.get("MYSQLDATABASE")

    if not (host and user and db):
        print("Missing required environment variables (MYSQLHOST/MYSQLUSER/MYSQLDATABASE).", file=sys.stderr)
        sys.exit(2)

    # If MYSQL_PUBLIC_URL looks like mysql://user:pass@host:port/db, prefer explicit vars
    # Ensure host doesn't contain protocol: strip if present
    if isinstance(host, str) and host.startswith("mysql://"):
        # Try to parse minimal form user:pass@host:port/db
        try:
            no_proto = host.split("mysql://", 1)[1]
            creds, hostdb = no_proto.split("@", 1)
            hostpart, dbpart = hostdb.rsplit("/", 1)
            host_only, port_only = hostpart.split(":") if ":" in hostpart else (hostpart, port)
            user_pass = creds.split(":")
            if not user:
                user = user_pass[0]
            if not password and len(user_pass) > 1:
                password = user_pass[1]
            host = host_only
            try:
                port = int(port_only)
            except Exception:
                pass
            if not db:
                db = dbpart
        except Exception:
            pass

    # If Railway exposes a TCP proxy (for connecting from outside), prefer it
    proxy_host = os.environ.get('RAILWAY_TCP_PROXY_DOMAIN') or os.environ.get('MYSQL_TCP_PROXY_DOMAIN') or None
    proxy_port = os.environ.get('RAILWAY_TCP_PROXY_PORT') or os.environ.get('MYSQL_TCP_PROXY_PORT') or None
    if proxy_host:
        host = proxy_host
        try:
            if proxy_port:
                port = int(proxy_port)
        except Exception:
            pass

    conn = pymysql.connect(host=host, port=port, user=user, password=password, db=db, charset='utf8mb4', cursorclass=pymysql.cursors.Cursor)
    return conn, db


def dump_database(outfile_path):
    conn, db = get_conn()
    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    with gzip.open(outfile_path, 'wt', encoding='utf-8') as out:
        out.write(f"-- Backup of database `{db}` created at {ts}\n")
        out.write("SET FOREIGN_KEY_CHECKS=0;\n\n")

        with conn.cursor() as cur:
            # Get tables
            cur.execute("SHOW FULL TABLES WHERE Table_Type = 'BASE TABLE';")
            tables = [row[0] for row in cur.fetchall()]

            for table in tables:
                print(f"Dumping table: {table}")
                # Get CREATE TABLE
                cur.execute(f"SHOW CREATE TABLE `{table}`;")
                create_stmt = cur.fetchone()[1]
                out.write(f"DROP TABLE IF EXISTS `{table}`;\n")
                out.write(create_stmt + ";\n\n")

                # Dump rows in batches
                cur.execute(f"SELECT * FROM `{table}`;")
                cols = [desc[0] for desc in cur.description]

                batch_size = 500
                rows = cur.fetchmany(batch_size)
                while rows:
                    values_lines = []
                    for row in rows:
                        escaped = []
                        for v in row:
                            if v is None:
                                escaped.append('NULL')
                            elif isinstance(v, (int, float)):
                                escaped.append(str(v))
                            else:
                                s = str(v)
                                s = escape_string(s)
                                escaped.append("'" + s + "'")
                        values_lines.append("(" + ",".join(escaped) + ")")

                    if values_lines:
                        out.write(f"INSERT INTO `{table}` (`" + "`,`".join(cols) + "`) VALUES\n")
                        out.write(",\n".join(values_lines) + ";\n\n")

                    rows = cur.fetchmany(batch_size)

        out.write("SET FOREIGN_KEY_CHECKS=1;\n")


if __name__ == '__main__':
    try:
        now = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        filename = f"backup-{now}.sql.gz"
        dump_database(filename)
        print(f"Backup written to {filename}")
    except pymysql.err.OperationalError as e:
        print("Error connecting to DB:", e, file=sys.stderr)
        sys.exit(3)
    except Exception as exc:
        print("Unexpected error:", exc, file=sys.stderr)
        sys.exit(4)
