# CLI Reference

Complete command-line interface documentation for MattStash. `mattstash --help` and
`mattstash <command> --help` always show the options of the version you have installed.

## Global Options

Accepted by every command, before or after the command name (`mattstash --db X get foo` and
`mattstash get foo --db X` are the same).

### Local Mode Options

```bash
--db PATH                    # KeePass database (default: ~/.config/mattstash/mattstash.kdbx, or MATTSTASH_DB_PATH)
--password PASSWORD          # Database password (alias: --db-password)
--db-password-file FILE      # Read the database password from FILE (surrounding whitespace is stripped)
```

The database password comes from, first match wins: `--password`/`--db-password` or `--db-password-file`
(giving both kinds is an error), `KDBX_PASSWORD`, `KDBX_PASSWORD_FILE`, then the sidecar
file `.mattstash.txt` next to the database (only exists if you chose `setup --sidecar`).

`--db-password` is the unambiguous spelling of `--password`. The two differ in exactly one place: for
`put --fields`, a bare `--password` is still read as the *entry* password (its historical meaning, now
deprecated), whereas `--db-password` and `--db-password-file` always mean the database password.

### Server Mode Options

```bash
--server-url URL            # MattStash server URL (enables server mode)
--api-key KEY               # API key for server authentication
--api-key-file FILE         # Read the API key from FILE (surrounding whitespace is stripped)
```

The API key comes from, first match wins: `--api-key`, `--api-key-file`, `MATTSTASH_API_KEY`,
`MATTSTASH_API_KEY_FILE` (`--api-key` together with `--api-key-file` is an error).

### Other Options

```bash
--verbose                   # Verbose output
--version                   # Print the version and exit
```

### Keeping secrets off the command line

Anything given in `argv` is visible to every local user (`ps`, `/proc/<pid>/cmdline`) and is saved in your
shell history. Prefer these forms:

| Instead of | Use |
|------------|-----|
| `--password PW` / `--db-password PW` | `--db-password-file FILE`, `KDBX_PASSWORD_FILE`, or `KDBX_PASSWORD` |
| `--api-key KEY` | `--api-key-file FILE`, `MATTSTASH_API_KEY_FILE`, or `MATTSTASH_API_KEY` |
| `put NAME --value SECRET` | `put NAME --value -` (reads stdin) or `put NAME --value-file FILE` |
| `put NAME --entry-password PW` | `--entry-password-stdin` or `--entry-password-file FILE` |
| `setup --password PW` | `setup --password-file FILE`, `--password-stdin`, or the interactive prompt |

Input read from stdin or a file has exactly one trailing newline removed (so `echo secret | mattstash put x --value -`
stores `secret`) and must not be empty. Only one option per invocation may read stdin.

## Environment Variables

| Variable | Meaning |
|----------|---------|
| `MATTSTASH_DB_PATH` | Default database path |
| `KDBX_PASSWORD` | Database password |
| `KDBX_PASSWORD_FILE` | File holding the database password (Docker/Kubernetes secrets) |
| `MATTSTASH_SERVER_URL` | Server URL (enables server mode) |
| `MATTSTASH_API_KEY` | Server API key |
| `MATTSTASH_API_KEY_FILE` | File holding the server API key |
| `MATTSTASH_ALLOW_INSECURE_HTTP` | `1`/`true`/`yes` silences the warning about sending the API key over plain `http://` |
| `MATTSTASH_ENABLE_CACHE`, `MATTSTASH_CACHE_TTL` | Connection caching (see [caching](caching.md)) |
| `MATTSTASH_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING` (default), `ERROR` |

See [configuration.md](configuration.md) for the full list.

## Mode Selection

**Local mode** (default): direct access to a KeePass database file, using `--db` and the database
password options.

**Server mode**: HTTP requests to a MattStash API server. Enabled by `--server-url` or
`MATTSTASH_SERVER_URL`; needs an API key. The local options (`--db`, `--password`, ...) are ignored.

| Command | Local | Server |
|---------|:-----:|:------:|
| `list`, `keys`, `get`, `put`, `delete`, `versions`, `db-url` | yes | yes |
| `env`, `exec` | yes | yes (custom property fields are not available) |
| `prune`, `backup`, `rotate-password` | yes | no: exits 1 with "not supported in server mode" |
| `setup`, `s3-test`, `config` | always local | |

Server-mode notes:

- Credential names are percent-encoded in the request path, so a name such as `db#prod` addresses exactly that
  name (the server may still reject characters it does not allow).
- The client verifies TLS certificates and does not follow redirects. If the URL is `http://` and the host is not
  `localhost`/a loopback address, one warning is logged because the API key travels in clear text; set
  `MATTSTASH_ALLOW_INSECURE_HTTP=1` to silence it for a trusted network. Plain HTTP is never refused.
- Error messages show the HTTP status and request path only: never the API key or the response body.
- A read-only server answers writes with HTTP 405 (`put`, `delete` then exit 1).

## Commands

### `setup` - Create a Database

Creates a new KeePass database. This is the **only** command that creates one.

```bash
mattstash setup [--sidecar | --generate | --password-file FILE | --password-stdin]
                [--force [--yes] [--no-backup]]
```

**Master password source** (first match wins): `--password-stdin`, `--password-file`, `--password`/`--db-password-file`,
`KDBX_PASSWORD` / `KDBX_PASSWORD_FILE`, `--sidecar` (random, stored next to the database), `--generate` (random,
printed once), otherwise an interactive prompt (asked twice). Non-interactive runs without any source fail.

**Options:**
- `--sidecar` - generate a password and store it in `<db dir>/.mattstash.txt` (0600). The key then sits beside the database.
- `--generate` - generate a password and print it once; nothing is stored.
- `--password-file FILE` / `--password-stdin` - read the password from a file / stdin.
- `--force` - replace existing files. Asks for confirmation (non-interactive runs need `--yes`) and backs up the
  existing database/sidecar to `<name>.bak-<timestamp>` first.
- `--no-backup` - with `--force`, skip the backup.

**Examples:**
```bash
mattstash setup                                   # prompt
mattstash setup --sidecar                         # convenient single-user setup
mattstash --db /srv/data/mattstash.kdbx setup --password-file /run/secrets/kdbx_password
mattstash setup --force --yes --sidecar           # replace (with backup)
```

**Exit codes:** `0` success, `1` failure, `8` refused to overwrite existing files.

### `list` - Show All Credentials

```bash
mattstash list [--show-password] [--json]
```

Every stored entry is listed, including each version of a versioned secret as its own row
(`name@0000000001`). Passwords are masked unless `--show-password` is given.

```
- api-token@0000000001 user=None url=None pwd='*****' tags=[]
- api-token@0000000002 user=None url=None pwd='*****' tags=[]
- production-db@0000000001 user='dbuser' url='db.internal:5432' pwd='*****' tags=[] notes='Production PostgreSQL'
```

### `keys` - List Credential Names

```bash
mattstash keys [--json]
```

Prints one title per line (versioned entries appear as `name@0000000001`).

### `get` - Retrieve a Credential

```bash
mattstash get <title> [--version N] [--show-password | --json | --raw [--field FIELD]]
```

**Options:**
- `--version N` - a specific version (default: the latest)
- `--show-password` - show the real password instead of `*****`
- `--json` - JSON output
- `--raw` - print **only** the secret followed by a newline, unmasked (implies `--show-password`); for scripts.
  Nothing else is ever written to stdout; diagnostics go to stderr. Mutually exclusive with `--json`.
- `--field {password,username,url,notes}` - with `--raw`, which field of a full credential to print
  (default `password`). A simple secret only has a password/value, so any other field is an error (exit 1).

**Output (simple secret):**
```
api-token
  value: *****
```

**Output (full credential):**
```
production-db
  username: dbuser
  password: *****
  url:      db.internal:5432
  tags:     
  notes/comments:
    Production PostgreSQL
```

**Scripting:**
```bash
TOKEN=$(mattstash get api-token --raw)                       # the latest value
DB_USER=$(mattstash get production-db --raw --field username)
mattstash get api-token --raw --version 1                    # an older version
curl -H "Authorization: Bearer $(mattstash get api-token --raw)" https://api.example.com/
```

An empty field (for example `--field url` on a credential without a URL) is also exit 2, so a script never
carries on with an empty value that merely looks like success. Works in local and server mode.

**Exit codes:** `0` success, `2` not found (or empty field with `--raw`), `1` invalid combination of options
(`--field` without `--raw`, a field a simple secret does not have), `6`/`7` database problems.

### `put` - Store/Update a Credential

Creates a new version of the credential. Two modes:

#### Simple secret mode (credstash-like)
```bash
mattstash put <title> --value -               # read the value from stdin (preferred)
mattstash put <title> --value-file FILE       # read the value from a file
mattstash put <title> --value VALUE           # value on the command line (visible via ps/history)
```

#### Full credential mode
```bash
mattstash put <title> [--fields] [--username U] [--url URL]
              [--entry-password-file FILE | --entry-password-stdin | --entry-password PW]
              [--notes TEXT] [--tag TAG]...
```

**Options:**
- `--value VALUE` - simple secret; `--value -` reads stdin
- `--value-file FILE` - simple secret from a file
- `--fields` - full credential mode (inferred when any of `--username`, `--url` or `--entry-password*` is given)
- `--username`, `--url` - fields of a full credential
- `--entry-password PW`, `--entry-password-file FILE`, `--entry-password-stdin` - the password stored in the
  entry (at most one; they select full credential mode)
- `--notes TEXT`, `--comment TEXT` (alias) - notes/comments
- `--tag TAG` - add a tag (repeatable)
- `--json` - JSON output

`--value`/`--value-file`/`--fields` are mutually exclusive, and `--value` cannot be combined with
`--username`, `--url` or `--entry-password*` (that would silently drop fields). A literal `-` value cannot be
stored with `--value`; use `--value-file`.

**The database password vs the entry password.** `--password`/`--db-password` and `--db-password-file` are the
password that *opens the database* (see [Global Options](#global-options)); `--entry-password*` is the password
*stored in the entry*. For backwards compatibility a bare `--password` together with `--fields` is still accepted as
the entry password, but it is **deprecated**: it logs a warning (secrets on the command line are visible to other
users) and will be removed. Use `--entry-password-file`/`--entry-password-stdin`, and `--db-password-file`
for the database.

**Examples:**
```bash
# Simple secret, value from stdin or a file (nothing on the command line)
printf '%s' "$TOKEN" | mattstash put api-token --value -
mattstash put api-token --value-file ./token.txt

# Full credential: the password from a file, the rest as options
mattstash put production-db --username dbuser --entry-password-file ./db-password \
  --url db.internal:5432 --notes "Production PostgreSQL" --tag production

# Entry password from stdin
pwgen 32 1 | mattstash put production-db --username dbuser --url db.internal:5432 --entry-password-stdin

# A new version of an existing secret (versions are created automatically)
mattstash put api-token --value-file ./rotated-token.txt
```

**Output:** `api-token: *****` for simple secrets (the value is never echoed), `production-db: OK` for full
credentials; `--json` prints the stored record with the secret masked.

### `delete` - Remove a Credential

```bash
mattstash delete <title> [--version N]
```

Without `--version`, the secret and **all** of its versions are removed. With `--version N`, only that version is
removed and the others (including the latest, if you delete an older one) stay.

```bash
mattstash delete old-api-key              # old-api-key: deleted
mattstash delete api-token --version 1    # api-token@0000000001: deleted
```

**Exit codes:** `0` deleted, `2` not found.

In server mode `--version N` is sent as `DELETE /api/v1/credentials/<name>?version=N`. The server must support that
parameter: an older server ignores it and would delete every version, so upgrade the server before using it.

### `prune` - Trim Version History

```bash
mattstash prune <title> --keep N
```

Deletes all but the newest `N` versions (`N` of at least 1) of a secret. Versions accumulate forever otherwise.
Local database only; in server mode it exits 1 with "not supported in server mode".

```
$ mattstash prune api-token --keep 2
api-token: pruned 3 version(s), kept 2
  deleted 0000000001
  deleted 0000000002
  deleted 0000000003
```

**Exit codes:** `0` success (also when there is nothing to prune), `1` invalid `--keep`, `2` the secret has no versions.

> Versions are a convenience history of values, **not an audit log**: they record what a secret used to be,
> not who changed it or when.

### `versions` - Show Version History

```bash
mattstash versions <title> [--json]
```

Prints the versions of a secret, oldest first, one per line:

```
0000000001
0000000002
```

### `db-url` - Generate a Database URL

Build a SQLAlchemy-compatible database connection URL from a credential
(username, password, `host:port` in the URL field, and a database name).

```bash
mattstash db-url <title> [--dialect DIALECT] [--driver DRIVER] [--database NAME] [--mask-password BOOL]
```

**Options:**
- `--dialect` - `postgresql` (default), `mysql` or `mariadb`. Can also be stored on the credential as the custom
  property `dialect`; the option wins.
- `--driver` - driver suffix. Default: `psycopg` for PostgreSQL, none for MySQL/MariaDB (SQLAlchemy's own default
  driver). Pass `''` for no suffix. Drivers are checked against an allow-list:

  | Dialect | Allowed drivers |
  |---------|-----------------|
  | `postgresql` | `psycopg`, `psycopg2`, `asyncpg`, `pg8000` |
  | `mysql` | `pymysql`, `mysqlconnector`, `asyncmy`, `aiomysql` |
  | `mariadb` | `mariadbconnector`, `pymysql` |

  An unknown dialect or a driver that does not belong to the dialect is an error.
- `--database` - database name (otherwise the custom property `database` or `dbname`)
- `--mask-password BOOL` - mask the password (default `true`; the masked URL omits it). Pass `false` to include it.

The custom property `sslmode` (or an override) adds `?sslmode=...` for **PostgreSQL only**; on MySQL/MariaDB it is
rejected with an error rather than silently dropped. User, password and database name are percent-encoded.
Use `sslmode=require` (or `verify-full`) in production.

**Examples:**
```bash
mattstash db-url production-db --database myapp_prod
# postgresql+psycopg://dbuser@db.internal:5432/myapp_prod

mattstash db-url mysql-db --dialect mysql --driver pymysql --database webapp
# mysql+pymysql://dbuser@mysql.internal:3306/webapp

mattstash db-url dev-db --database myapp_dev --mask-password false
```

**Exit codes:** `5` the URL could not be built (message on stderr).

### `env` - Print Secrets as Environment Variables

For containers, pods, CI and scripts. Selects secrets and prints them on stdout (the secrets reach stdout only
because you asked for them, like `get --raw`; nothing else is printed there and nothing is logged).

```bash
mattstash env [--prefix P] [--map ENVVAR=TITLE[:FIELD]]... [--format shell|dotenv|json]
              [--strip-prefix | --no-strip-prefix] [--upper]
```

**Selection** (at least one of `--prefix`/`--map` is required; the latest version of each secret is used):
- `--prefix P` - every secret whose title starts with `P` becomes a variable named after the title. The prefix is
  removed (`--no-strip-prefix` keeps it), characters other than `A-Z a-z 0-9 _` become `_`, and names are
  upper-cased with `--upper`. Secrets with an empty password are skipped with a warning.
- `--map ENVVAR=TITLE[:FIELD]` - one explicit variable (repeatable). `FIELD` is `password` (default), `username`,
  `url`, `notes` or the name of a custom property. The field is taken after the last `:`, so a title that itself
  contains `:` needs an explicit field (`X=svc:prod:password`). Server mode only offers the four standard fields.

Names must match `[A-Za-z_][A-Za-z0-9_]*`. Nothing is printed if a name is invalid, two secrets would produce the
same name (the error names the titles, never the values), a mapped secret or field does not exist, or a prefix
matches nothing.

**Formats:**
- `shell` (default) - `export NAME='value'`, quoted with `shlex.quote`; safe to `eval` for any value (spaces, quotes,
  newlines, `$(...)`, backticks).
- `dotenv` - `NAME=value`; values with anything but `A-Za-z0-9_./:@%+,=-` are single-quoted, and values containing
  a quote or a line break are double-quoted with `\\`, `\"`, `\n`, `\r`, `\$` escapes. Dotenv dialects differ, so
  prefer `shell` or `json` when values are unusual.
- `json` - one object `{"NAME": "value"}`.

**Examples:**
```bash
eval "$(mattstash env --prefix myapp/ --upper)"                    # DB_PASSWORD, API_KEY, ...
mattstash env --map PGPASSWORD=production-db --map PGUSER=production-db:username --map PGHOST=production-db:url
mattstash env --prefix myapp/ --upper --format dotenv > /dev/shm/app.env    # for docker run --env-file
mattstash env --prefix myapp/ --format json | jq .
```

Do not write the output to disk or logs unless you mean to; prefer `exec`.

**Exit codes:** `0` success, `1` invalid names/mappings/collisions, `2` secret or prefix not found, `6`/`7` database problems.

### `exec` - Run a Command with Secrets in its Environment

```bash
mattstash exec [--prefix P] [--map ENVVAR=TITLE[:FIELD]]... [--strip-prefix | --no-strip-prefix] [--upper]
               [--override] -- COMMAND [ARGS...]
```

Builds the same environment as `env` and then **replaces** the process with `COMMAND` (`execve`): the command's exit
status is the process's exit status, no shell is involved, and nothing is written to disk or stdout. Variables that
are already set win unless you pass `--override`. The command is looked up with your original `PATH` (a secret
named `PATH` cannot redirect the lookup). Everything after `--` belongs to the command; options must come before it.

```bash
mattstash exec --prefix myapp/ --upper -- ./server --port 8080
mattstash exec --map DATABASE_PASSWORD=production-db -- psql -h db.internal -U dbuser myapp
mattstash exec --override --map API_TOKEN=api-token -- ./deploy.sh
```

**Exit codes:** the command's own status; `1` no command given or invalid selection, `2` secret not found,
`126` the command cannot be executed, `127` the command was not found (as with `env`/`xargs`), `6`/`7` database problems.

**Containers and Kubernetes.** The container needs the database and its password, not the server:

```yaml
containers:
  - name: app
    command: ["mattstash", "exec", "--prefix", "myapp/", "--upper", "--", "/app/server"]
    env:
      - {name: MATTSTASH_DB_PATH, value: /secrets/store/mattstash.kdbx}   # mounted read-only
      - {name: KDBX_PASSWORD_FILE, value: /secrets/key/password}          # a different mount
```

or, with a MattStash server, `MATTSTASH_SERVER_URL` and `MATTSTASH_API_KEY_FILE` instead.

### `backup` - Copy the Database

```bash
mattstash backup [DEST] [--force]
```

Writes a consistent copy of the database file while holding the write lock (it cannot interleave with a writer),
with mode `0600`, to a temp file that is then renamed into place. Prints the path of the backup (nothing else), so
`BAK=$(mattstash backup)` works. Local database only.

- `DEST` - a file, or an existing directory (the default file name is used inside it). Default:
  `<db>.bak-<UTC timestamp>` next to the database.
- `--force` - replace `DEST` if it exists (otherwise exit 8 and the file is untouched).

The backup is the encrypted file as it is: it needs no password to create and is opened with the master password
that was current at the time. The sidecar file is not copied.

**Exit codes:** `0` success, `6` no database file, `7` could not get the write lock in time, `8` `DEST` exists.

### `rotate-password` - Change the Master Password

```bash
mattstash rotate-password [--new-password-file FILE | --new-password-stdin | --generate] [--no-backup]
```

Re-keys the database under the write lock. The current password comes from the usual sources (it must open the
database, otherwise nothing changes). Steps: copy the database first (`<db>.bak-<timestamp>`, skipped with
`--no-backup`), re-key and save it, re-open it with the new password to prove it works, and, if a sidecar file
exists, replace it atomically (mode 0600) with the new password.

**New password source:** `--new-password-file FILE` (surrounding whitespace stripped, like `KDBX_PASSWORD_FILE`),
`--new-password-stdin` (first line), `--generate` (random; printed once), or, when stdin is a terminal, a prompt asked
twice. Without any source and without a terminal the command fails. A password with leading/trailing whitespace is
refused while a sidecar exists, because password files are read back stripped.

The backup still opens with the **old** password: delete it once you have verified the new one. Anything that holds the
old password - `KDBX_PASSWORD`/`KDBX_PASSWORD_FILE`, the secret mounted into a server - stops working until it is
updated (the command warns if those variables are set in its own environment).

**Exit codes:** `0` success, `6` no database file, `7` wrong or missing current password, or the write lock timed out, `1` no/invalid new
password, or the database was re-keyed but the sidecar could not be updated (the new password is printed anyway when
`--generate` was used).

### `s3-test` - Test S3 Connectivity

Create an S3 client from a credential and optionally test bucket access.

```bash
mattstash s3-test <title> [--region R] [--addressing path|virtual] [--signature-version V]
                  [--retries-max-attempts N] [--bucket NAME] [--quiet]
```

The credential's URL is the S3 endpoint, its username the access key and its password the secret key.

**Options:**
- `--region` - AWS region (default `us-east-1`)
- `--addressing` - `path` (default) or `virtual`
- `--signature-version` - default `s3v4`
- `--retries-max-attempts` - default 10
- `--bucket NAME` - also issue a `HeadBucket`
- `--quiet` - print nothing, exit code only

**Output:** the endpoint line goes to **stderr** (unless `--quiet`), the result to stdout:
```
[mattstash] Using endpoint=https://s3.amazonaws.com, region=us-east-1, addressing=path
[mattstash] S3 client created successfully
```

**Exit codes:** `3` client creation failed, `4` bucket access failed.

### `config` - Generate an Example Configuration File

```bash
mattstash config [--output PATH]
```

Needs PyYAML (`pip install "mattstash[config]"`). See [configuration.md](configuration.md).

### `server` - Server Quick Start

`mattstash server` prints how to run the API server (a separate Docker image, not a CLI subcommand).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | generic failure / invalid input (also: operation not supported in server mode) |
| 2 | the requested secret does not exist |
| 3 / 4 | `s3-test`: client creation / `HeadBucket` failed |
| 5 | `db-url`: URL could not be built |
| 6 | database file not found (run `mattstash setup`) |
| 7 | database cannot be opened: wrong/missing password, corrupt file, lock timeout |
| 8 | `setup` / `backup` refused to overwrite existing files |
| 126 / 127 | `exec`: the command could not be executed / was not found |
