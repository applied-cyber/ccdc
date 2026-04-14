#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime

PII_COLUMNS = {
    "user", "username", "login", "name", "given_name", "middle_name", "first_name",
    "last_name", "full_name", "display_name", "nickname", "email", "mail", "phone",
    "telephone", "tel", "mobile", "fax", "address", "address1", "address2", "street",
    "city", "state", "province", "region", "zip", "postal", "postcode", "country",
    "county", "ssn", "sin", "tax_id", "tin", "ein", "dob", "birth", "birthday",
    "company", "organization", "org", "customer", "client", "contact", "person",
    "profile", "owner", "account", "tenant", "member", "subscriber", "ip",
}
HASH_COLUMNS = {"password", "passwd", "passhash", "password_hash", "pwd", "hash", "digest"}
MYSQL_SYSTEM_TABLES = {
    "global_priv", "user", "db", "tables_priv", "columns_priv", "procs_priv", "proxies_priv",
    "roles_mapping", "default_roles", "password_reuse_check_history",
}
MYSQL_SYSTEM_HASH_COLUMNS = {"authentication_string", "password", "auth_string", "priv"}
PERSON_TABLES = {
    "user", "users", "customer", "customers", "client", "clients", "contact", "contacts",
    "profile", "profiles", "person", "people", "member", "members", "employee",
    "employees", "account", "accounts", "patient", "patients", "lead", "leads",
    "order", "orders", "address", "addresses",
}
SAFE_COLUMN_PATTERNS = {
    "asset", "alias", "path", "slug", "element", "folder", "type", "language",
    "extension", "client", "action", "rules", "params", "metadata", "images", "urls",
    "template", "hash_id", "key", "option", "namespace", "provider", "driver", "host",
}
USE_DB_RE = re.compile(r"^USE `([^`]+)`;$")
CREATE_TABLE_RE = re.compile(r"^CREATE TABLE (?:(?:`([^`]+)`\.)?`([^`]+)`) \($")
COLUMN_DEF_RE = re.compile(r"^\s*`([^`]+)`\s+")
INSERT_RE = re.compile(
    r"^INSERT INTO (?:(?:`([^`]+)`\.)?`([^`]+)`)(?: \(([^)]+)\))? VALUES\s*(.*);$",
    re.S,
)
EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$", re.I)
PHONE_RE = re.compile(r"^\+?[\d(). \-]{7,24}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]+$", re.I)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
POSTAL_RE = re.compile(r"^\d{5}(?:-\d{4})?$")
CARD_RE = re.compile(r"^(?:\d[ -]?){13,19}$")
ADDRESS_RE = re.compile(r"^\d{1,6}\s+[A-Za-z0-9][A-Za-z0-9 .'\-#]{4,}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,79}$")
LIKELY_HASH_RE = re.compile(
    r"^(?:"
    r"\*[0-9A-F]{40}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|(?:\$[A-Za-z0-9_]+\$)+2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$argon2(?:id|i|d)\$[^\s]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+argon2(?:id|i|d)\$[^\s]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$[156]\$[./A-Za-z0-9]{8,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+[156]\$[./A-Za-z0-9]{8,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$y\$[./A-Za-z0-9$]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+y\$[./A-Za-z0-9$]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$(?:pbkdf2|pbkdf2-sha256|pbkdf2-sha512|scrypt|yescrypt)[^\s]{12,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+(?:pbkdf2|pbkdf2-sha256|pbkdf2-sha512|scrypt|yescrypt)[^\s]{12,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*(?:sha1|sha224|sha256|sha384|sha512):[^\s]{16,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*[0-9a-f]{32,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*[A-Za-z0-9+/=]{40,}"
    r")$"
)
HASH_FRAGMENT_RE = re.compile(
    r"(?:"
    r"\*[0-9A-F]{40}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|(?:\$[A-Za-z0-9_]+\$)+2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$argon2(?:id|i|d)\$[^\s\"'\\,;]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+argon2(?:id|i|d)\$[^\s\"'\\,;]{20,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*\$(?:pbkdf2|pbkdf2-sha256|pbkdf2-sha512|scrypt|yescrypt)[^\s\"'\\,;]{12,}"
    r"|(?:\$[A-Za-z0-9_]+\$)+(?:pbkdf2|pbkdf2-sha256|pbkdf2-sha512|scrypt|yescrypt)[^\s\"'\\,;]{12,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*(?:sha1|sha224|sha256|sha384|sha512):[^\s\"'\\,;]{16,}"
    r"|(?:\$[A-Za-z0-9_]+\$)*[0-9a-f]{32,}"
    r")"
)


def parse_args():
    parser = argparse.ArgumentParser(description="Create a full MySQL dump and a redacted copy.")
    parser.add_argument(
        "--output",
        help="Raw dump path. Defaults to ./mysql-all-databases-YYYYmmdd-HHMMSS.sql",
    )
    parser.add_argument(
        "--redacted-output",
        help="Redacted dump path. Defaults to <output>-redacted.sql",
    )
    return parser.parse_args()


def default_paths(args):
    if args.output:
        output = os.path.abspath(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = os.path.abspath(f"mysql-all-databases-{ts}.sql")
    if args.redacted_output:
        redacted = os.path.abspath(args.redacted_output)
    else:
        base, ext = os.path.splitext(output)
        redacted = f"{base}-redacted{ext or '.sql'}"
    return output, os.path.abspath(redacted)


def run_dump(output_path):
    with open(output_path, "wb") as output:
        completed = subprocess.run(["mysqldump", "--all-databases"], stdout=output)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def split_sql_items(text):
    items, start, quote, escape, depth = [], 0, None, False, 0
    for i, ch in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append(text[start:i].strip())
            start = i + 1
    items.append(text[start:].strip())
    return items


def split_tuples(values):
    tuples, start, quote, escape, depth = [], None, None, False, 0
    for i, ch in enumerate(values):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start is not None:
                tuples.append(values[start : i + 1])
    return tuples


def update_statement_state(text, quote=None, escape=False):
    for ch in text:
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == ";":
            return quote, escape, True
    return quote, escape, False


def decode_sql_string(token):
    if token == "NULL":
        return None
    if len(token) >= 2 and token[0] == token[-1] == "'":
        body = token[1:-1]
        out, i = [], 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                out.append({"0": "\0", "n": "\n", "r": "\r", "t": "\t", "Z": "\x1a"}.get(nxt, nxt))
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    return token


def encode_sql_string(value):
    if value is None:
        return "NULL"
    return "'" + (
        value.replace("\\", "\\\\")
        .replace("\0", "\\0")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\x1a", "\\Z")
        .replace("'", "\\'")
    ) + "'"


def xor_hash(value, mask):
    raw = bytes.fromhex(value) if HEX_RE.fullmatch(value) and len(value) % 2 == 0 else value.encode()
    mixed = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(raw))
    return mixed.hex() if HEX_RE.fullmatch(value) and len(value) % 2 == 0 else mixed.hex()


def digest_parts(value, mask):
    digest = hashlib.sha256(mask + value.encode()).hexdigest()
    digits = "".join(ch for ch in digest if ch.isdigit())
    return digest, (digits * 4)


def unique_token(value, mask, prefix="redacted"):
    digest, _ = digest_parts(value, mask)
    return f"{prefix}_{digest[:12]}"


def is_likely_hash(value):
    return bool(LIKELY_HASH_RE.fullmatch(value))


def is_mysql_system_hash_context(column, table):
    return table.lower() in MYSQL_SYSTEM_TABLES and column.lower() in MYSQL_SYSTEM_HASH_COLUMNS


def redact_embedded_hashes(value, table, column, mask):
    if is_mysql_system_hash_context(column, table):
        return value
    return HASH_FRAGMENT_RE.sub(lambda m: xor_hash(m.group(0), mask), value)


def scrub_raw_line(line, current_table, mask):
    if current_table and current_table.lower() in MYSQL_SYSTEM_TABLES:
        return line
    return HASH_FRAGMENT_RE.sub(lambda m: xor_hash(m.group(0), mask), line)


def finalize_redacted_file(path, mask):
    current_table = ""
    changed = 0
    temp_path = f"{path}.tmp"
    with open(path, "r", encoding="utf-8", errors="replace") as src, open(temp_path, "w", encoding="utf-8") as dst:
        for line in src:
            if match := CREATE_TABLE_RE.match(line):
                current_table = match.group(2)
            elif line.startswith("INSERT INTO "):
                match = INSERT_RE.match(line.rstrip("\n"))
                if match:
                    current_table = match.group(2)
                else:
                    parts = line.split("`")
                    if len(parts) >= 2:
                        current_table = parts[-2]
            scrubbed = scrub_raw_line(line, current_table, mask)
            changed += scrubbed != line
            dst.write(scrubbed)
    os.replace(temp_path, path)
    return changed


def redact_literal(value, table, mask):
    if value is None:
        return None
    tbl = table.lower()
    digest, digits = digest_parts(value, mask)
    if is_likely_hash(value):
        return xor_hash(value, mask)
    if IPV4_RE.fullmatch(value):
        return f"10.{int(digits[0:3]) % 256}.{int(digits[3:6]) % 256}.{int(digits[6:9]) % 256}"
    if EMAIL_RE.fullmatch(value):
        return f"user-{digest[:12]}@example.invalid"
    if PHONE_RE.fullmatch(value):
        return f"555-{digits[0:3]}-{digits[3:7]}"
    if UUID_RE.fullmatch(value):
        return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-a{digest[17:20]}-{digest[20:32]}"
    if SSN_RE.fullmatch(value):
        return f"{digits[0:3]}-{digits[3:5]}-{digits[5:9]}"
    if POSTAL_RE.fullmatch(value):
        return digits[:5]
    if ADDRESS_RE.fullmatch(value):
        return f"{int(digits[:4]) or 100} Redacted Ave {digest[:6]}"
    digits = re.sub(r"\D", "", value)
    if 13 <= len(digits) <= 19 and CARD_RE.fullmatch(value):
        return f"4000 {digits[0:4]} {digits[4:8]} {digits[8:12]}"
    if any(key in tbl for key in PERSON_TABLES) and NAME_RE.fullmatch(value) and " " in value:
        return unique_token(value, mask, "person")
    return value


def is_safe_context(column, table):
    col = column.lower()
    return any(key in col for key in SAFE_COLUMN_PATTERNS)


def looks_like_title_or_label(value):
    if not NAME_RE.fullmatch(value):
        return False
    words = value.split()
    if not words or len(words) > 6:
        return False
    return any(any(ch.isupper() for ch in word[:1]) for word in words)


def should_preserve_generic_value(column, value):
    col = column.lower()
    if col in {"name", "title", "label", "subject"} and looks_like_title_or_label(value):
        return True
    if col in {"path", "alias", "slug", "element", "type", "folder", "language", "option", "namespace", "provider", "driver"}:
        return True
    if value.startswith("{") or value.startswith("["):
        return True
    return False


def redact_value(column, value, table, mask):
    if value is None:
        return None
    col = column.lower()
    if is_mysql_system_hash_context(column, table):
        return value
    replaced = redact_embedded_hashes(value, table, column, mask)
    if replaced != value:
        return replaced
    if should_preserve_generic_value(column, value):
        if any(key in col for key in HASH_COLUMNS) and is_likely_hash(value):
            return xor_hash(value, mask)
        if EMAIL_RE.fullmatch(value) or PHONE_RE.fullmatch(value) or UUID_RE.fullmatch(value) or IPV4_RE.fullmatch(value) or SSN_RE.fullmatch(value):
            return redact_literal(value, table, mask)
        return value
    if is_safe_context(column, table):
        if any(key in col for key in HASH_COLUMNS) and is_likely_hash(value):
            return xor_hash(value, mask)
        if EMAIL_RE.fullmatch(value) or PHONE_RE.fullmatch(value) or UUID_RE.fullmatch(value) or IPV4_RE.fullmatch(value) or SSN_RE.fullmatch(value):
            return redact_literal(value, table, mask)
        return value
    if any(key in col for key in HASH_COLUMNS):
        return redact_literal(value, table, mask)
    pii = any(key in col for key in PII_COLUMNS) or any(key in table.lower() for key in PERSON_TABLES)
    if not pii:
        return redact_literal(value, "", mask)
    if NAME_RE.fullmatch(value) and " " in value:
        return unique_token(value, mask, "person")
    if value and value != "0":
        redacted = redact_literal(value, table, mask)
        return unique_token(value, mask) if redacted == value else redacted
    return redact_literal(value, table, mask)


def redact_insert(line, schema, mask):
    match = INSERT_RE.match(line.rstrip("\n"))
    if not match:
        return line, 0
    _, table, column_text, values_text = match.groups()
    columns = [part.strip().strip("`") for part in split_sql_items(column_text)] if column_text else schema.get(table, [])
    redacted = []
    replacements = 0
    for item in split_tuples(values_text):
        parts = split_sql_items(item[1:-1])
        if columns and len(parts) != len(columns):
            return line, 0
        updated = []
        for index, part in enumerate(parts):
            value = decode_sql_string(part)
            if value is None or (len(part) < 2 or part[0] != "'" or part[-1] != "'"):
                updated.append(part)
                continue
            if columns:
                new_value = redact_value(columns[index], value, table, mask)
            else:
                new_value = redact_literal(value, table, mask)
            replacements += new_value != value
            updated.append(encode_sql_string(new_value))
        redacted.append("(" + ", ".join(updated) + ")")
    return f"INSERT INTO `{table}`" + (f" ({column_text})" if column_text else "") + " VALUES " + ", ".join(redacted) + ";\n", replacements


def create_redacted_dump(raw_path, redacted_path):
    mask = secrets.token_bytes(16)
    schema, current_db, current_table = {}, None, None
    replacements = 0
    with open(raw_path, "r", encoding="utf-8", errors="replace") as src, open(redacted_path, "w", encoding="utf-8") as dst:
        insert_lines = []
        insert_quote = None
        insert_escape = False
        for line in src:
            if insert_lines:
                insert_lines.append(line)
                insert_quote, insert_escape, complete = update_statement_state(line, insert_quote, insert_escape)
                if complete:
                    insert_sql = "".join(insert_lines)
                    match = INSERT_RE.match(insert_sql.rstrip("\n"))
                    if match:
                        table = match.group(2)
                        redacted_sql, count = redact_insert(insert_sql, {table: schema.get(table, [])}, mask)
                        replacements += count
                        dst.write(redacted_sql)
                    else:
                        scrubbed = scrub_raw_line(insert_sql, current_table[1] if current_table else "", mask)
                        replacements += scrubbed != insert_sql
                        dst.write(scrubbed)
                    insert_lines = []
                    insert_quote = None
                    insert_escape = False
                continue
            if match := USE_DB_RE.match(line):
                current_db = match.group(1)
            elif match := CREATE_TABLE_RE.match(line):
                db_name = match.group(1) or current_db
                current_table = (db_name, match.group(2))
                schema.setdefault(current_table[1], [])
            elif current_table:
                if line.startswith(")"):
                    current_table = None
                elif match := COLUMN_DEF_RE.match(line):
                    schema[current_table[1]].append(match.group(1))
            if line.startswith("INSERT INTO "):
                insert_quote, insert_escape, complete = update_statement_state(line)
                if not complete:
                    insert_lines = [line]
                    continue
            if match := INSERT_RE.match(line.rstrip("\n")):
                table = match.group(2)
                redacted_line, count = redact_insert(line, {table: schema.get(table, [])}, mask)
                replacements += count
                dst.write(redacted_line)
            else:
                scrubbed = scrub_raw_line(line, current_table[1] if current_table else "", mask)
                replacements += scrubbed != line
                dst.write(scrubbed)
        if insert_lines:
            trailing = "".join(insert_lines)
            scrubbed = scrub_raw_line(trailing, current_table[1] if current_table else "", mask)
            replacements += scrubbed != trailing
            dst.write(scrubbed)
    replacements += finalize_redacted_file(redacted_path, mask)
    return replacements


def main():
    args = parse_args()
    output_path, redacted_path = default_paths(args)
    temp_raw = None
    if output_path == redacted_path:
        fd, temp_raw = tempfile.mkstemp(prefix="mysqldump-raw-", suffix=".sql")
        os.close(fd)
        raw_path = temp_raw
    else:
        raw_path = output_path
    try:
        run_dump(raw_path)
        replacements = create_redacted_dump(raw_path, redacted_path)
    finally:
        if temp_raw and os.path.exists(temp_raw):
            os.unlink(temp_raw)
    if raw_path == output_path:
        print(f"Raw dump: {raw_path}")
    else:
        print("Raw dump: temporary file removed after redaction")
    print(f"Redacted dump: {redacted_path}")
    print(f"Redactions: {replacements}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
