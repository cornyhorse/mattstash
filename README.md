## License

`mattstash` itself is licensed under the [MIT License](LICENSE).

### Dependency Note
This project depends on [`pykeepass`](https://github.com/libkeepass/pykeepass), which is licensed under the GNU General Public License v3 (GPL-3.0).
Because of this dependency, **any redistribution of `mattstash` or derivative works must also comply with the GPL-3.0 terms**.

In plain English:
- You can freely use, modify, and integrate `mattstash` in your own projects.
- If you distribute software that includes `mattstash`, the GPL-3.0 requirements from `pykeepass` will apply to your project.
- If you only use `mattstash` internally (not distributing your product), you are not affected by the GPL redistribution terms.

[`boto3`](https://github.com/boto/boto3), which is used for optional S3 client support, is licensed under the Apache 2.0 license, which is permissive and fully compatible with MIT.

Additionally, `mattstash` supports optional database-related dependencies for building connection URLs. These include `sqlalchemy` (MIT License) and `psycopg` (LGPL). These packages are not required for the core functionality of `mattstash` and are only needed if you use the database helper features.

## CLI

After installation, a `mattstash` command is available.

### Installation

```bash
pip install "mattstash"            # core only
pip install "mattstash[s3]"        # core + boto3 for S3 helpers
```

### Defaults & bootstrap

- Default DB path: `~/.credentials/mattstash.kdbx`
- Default sidecar password file: `~/.credentials/.mattstash.txt`
- On first run, if **both** files are missing, `mattstash` bootstraps them:
  - Generates a strong password, writes the sidecar with `0600` permissions
  - Creates an empty KeePass database at the default path

You can also run `mattstash setup` explicitly to force bootstrapping and configuration. This command creates the database and sidecar password file at the default location unless overridden with `--db`.

```bash
mattstash setup
```

You can override the DB path globally with `--db PATH` or via the Python API `MattStash(path=...)`.

### Commands

```bash
# List all entries
mattstash list
mattstash list --json
mattstash list --show-password

# Get one entry by title (supports two modes)
# 1) Simple key/value secret style (CredStash-like), where only the password field is used
mattstash get "MySecret"
mattstash get "MySecret" --json
mattstash get "MySecret" --show-password

# 2) Full credential dict style with username, password, url, notes
mattstash get "My Service"
mattstash get "My Service" --json
mattstash get "My Service" --show-password

# Add or update an entry (supports two modes)
# 1) Simple key/value secret style (CredStash-like), only password provided with --value
mattstash put "MySecret" --value SECRET_PASSWORD

# 2) Full credential dict style with username, password, url, notes
mattstash put "My Service" --username USERNAME --password PASSWORD --url URL --notes NOTES

# Delete an entry
mattstash delete "My Service"

# List all keys (entry titles)
mattstash keys

# Show versions/history of an entry
mattstash versions "My Service"
mattstash versions "My Service" --json

# Use `get_s3_client(...)` to build a ready-to-use boto3 S3 client from a KeePass entry
mattstash s3-test "Hetzner S3" --bucket my-bucket
mattstash s3-test "Hetzner S3" --addressing virtual --region us-east-1
mattstash s3-test "Hetzner S3" --quiet   # no output, exit code only

# Build a database connection URL from a KeePass entry
mattstash db-url "My Database" --database mydb
```

### Adding S3 credentials

To add a credential specifically for S3 connectivity, use the `put` command with the following fields:

- `--username` for the AWS access key ID
- `--password` for the AWS secret access key
- `--url` for the S3 endpoint URL
- `--notes` for any additional information

Example:

```bash
mattstash put "Hetzner S3" --username KEY --password SECRET --url https://endpoint --notes "Hetzner S3 storage"
```

The `s3-test` command expects the AWS-style key, secret, and endpoint to be stored in these fields in the KeePass entry.

You can also use the Python API to fetch S3 credentials and create a boto3 client using the helper function `get_s3_client`, which returns a ready-to-use authenticated boto3 S3 client.

Example using the module-level helper:

```python
from mattstash.s3 import get_s3_client
from mattstash.core import MattStash

client = get_s3_client("Hetzner S3")
# Upload a file
client.upload_file('localfile.txt', 'my-bucket', 'remote/path/localfile.txt')
```

Or using the instance method:

```python
from mattstash.core import MattStash

stash = MattStash()
client = stash.get_s3_client("Hetzner S3")
# Upload a file
client.upload_file('localfile.txt', 'my-bucket', 'remote/path/localfile.txt')
```

### Adding database credentials

To add a credential for database connectivity, use the `put` command with these fields:

- `--username` for the database user
- `--password` for the database password
- `--url` for the database host URL (must include port)
- `--notes` for any additional information

Example:

```bash
mattstash put "My Database" --username dbuser --password dbpass --url 127.0.0.1:5432 --notes "Postgres DB"
```

You can then build a Postgres/SQLAlchemy connection URL using the `db-url` command:

```bash
mattstash db-url "My Database" --database mydb
```

The tool validates the URL format and requires that the `url` field includes a port number.

Global options:

- `--db PATH` — path to the `.kdbx` database (default: `~/.credentials/mattstash.kdbx`)
- `--password VALUE` — override DB password (otherwise read from sidecar or `KDBX_PASSWORD`)
- `--verbose` — extra logging (CLI subcommands may also support `--quiet`)

Subcommand options:

- `list`: `--json`, `--show-password`
- `get`: `--json`, `--show-password`
- `keys`: (no options)
- `put`: `--value`, `--username`, `--password`, `--url`, `--notes`
- `delete`: (no options)
- `versions`: `--json`
- `s3-test`: `--region`, `--addressing {path,virtual}`, `--signature-version`, `--retries-max-attempts`, `--bucket`, `--quiet`
- `db-url`: `--database` (required; database name), `--mask-password` (optional, default true)

### Exit codes

- `0` — success
- `2` — entry not found (for `get`)
- `3` — failed to create S3 client
- `4` — S3 HeadBucket failed

### Examples

```bash
# Minimal list
mattstash list

# Get a credential as JSON (good for scripting)
mattstash get "CI Token" --json

# List all keys (entry titles)
mattstash keys

# Add or update an S3 credential
mattstash put "Hetzner S3" --username KEY --password SECRET --url https://endpoint

# Delete an old key
mattstash delete "old-key"

# Show versions/history for an entry
mattstash versions "Hetzner S3"

# S3 test against a Hetzner/MinIO-style endpoint stored in KeePass entry "objectstore"
mattstash s3-test "objectstore" --bucket cornyhorse-data

# Build a Postgres connection URL from a KeePass entry
mattstash db-url "My Database" --database mydb
```

## Python API usage

You can also use `mattstash` programmatically with the Python API. Here are examples that mirror the CLI commands:

```python
from mattstash.core import MattStash

stash = MattStash()

# List all entries
for entry in stash.list():
    print(entry['title'])

# List all entries as JSON (dictionary)
entries = list(stash.list())
print(entries)

# Get one entry by title (returns dict with fields)
entry = stash.get("My Service")
print(entry)

# Get a simple secret (password only)
secret = stash.get("MySecret")  # returns dict with 'password' field

# Add or update an entry (full credential dict style)
stash.put("My Service", username="user", password="pass", url="https://example.com", notes="notes")

# Add or update a simple secret (password only)
stash.put("MySecret", value="mysecretpassword")

# Delete an entry
stash.delete("My Service")

# List all keys (entry titles)
keys = stash.keys()
print(keys)

# Show versions/history of an entry
versions = stash.versions("My Service")
for version in versions:
    print(version)

# Use `get_s3_client(...)` to create a ready-to-use boto3 S3 client from a KeePass entry

from mattstash.s3 import get_s3_client

client = get_s3_client("Hetzner S3")
# Example: upload a file
client.upload_file('localfile.txt', 'my-bucket', 'remote/path/localfile.txt')

# Or using the instance method
client2 = stash.get_s3_client("Hetzner S3")
client2.upload_file('localfile.txt', 'my-bucket', 'remote/path/localfile.txt')
```

### Database connection URL support

You can add database credentials similarly using `--username`, `--password`, `--url` (including port), and `--notes` fields:

```python
stash.put("My Database", username="dbuser", password="dbpass", url="127.0.0.1:5432", notes="Postgres DB")
```

To build a full SQLAlchemy/Postgres connection URL, use the `get_db_url` method:

```python
# Build a connection URL with password masked (default)
url = stash.get_db_url("My Database", database="mydb")
print(url)  # e.g. postgresql://dbuser:****@127.0.0.1:5432/mydb

# Build a connection URL with password visible
url_unmasked = stash.get_db_url("My Database", database="mydb", mask_password=False)
print(url_unmasked)  # e.g. postgresql://dbuser:dbpass@127.0.0.1:5432/mydb
```

Note that the tool validates that the `url` field includes a port and that the resulting URL is valid for your database driver.
