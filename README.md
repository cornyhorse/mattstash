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

You can override the DB path globally with `--db PATH` or via the Python API `MattStash(path=...)`.

### Commands

```bash
# List all entries
mattstash list
mattstash list --json
mattstash list --show-password

# Get one entry by title
mattstash get "My Service"
mattstash get "My Service" --json
mattstash get "My Service" --show-password

# Build an S3 client from a KeePass entry and test connectivity
mattstash s3-test "Hetzner S3" --bucket my-bucket
mattstash s3-test "Hetzner S3" --addressing virtual --region us-east-1
mattstash s3-test "Hetzner S3" --quiet   # no output, exit code only
```

Global options:

- `--db PATH` — path to the `.kdbx` database (default: `~/.credentials/mattstash.kdbx`)
- `--password VALUE` — override DB password (otherwise read from sidecar or `KDBX_PASSWORD`)
- `--verbose` — extra logging (CLI subcommands may also support `--quiet`)

Subcommand options:

- `list`: `--json`, `--show-password`
- `get`: `--json`, `--show-password`
- `s3-test`: `--region`, `--addressing {path,virtual}`, `--signature-version`, `--retries-max-attempts`, `--bucket`, `--quiet`

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

# S3 test against a Hetzner/MinIO-style endpoint stored in KeePass entry "objectstore"
mattstash s3-test "objectstore" --bucket cornyhorse-data
```

## Smoke tests (pytest examples)

Create `tests/test_smoke.py` with:

```python
import subprocess
import sys

def run_cli(*args):
  cmd = [sys.executable, "-m", "mattstash.core", *args]
  return subprocess.run(cmd, capture_output=True, text=True)

def test_list_exits_zero():
  # On a fresh machine this will bootstrap DB+sidecar on first run
  proc = run_cli("list")
  assert proc.returncode == 0

def test_get_not_found_exits_2():
  proc = run_cli("get", "definitely-not-present")
  assert proc.returncode == 2
```

Or, if you've exposed the console script via `pyproject.toml`:

```python
import subprocess

def run_cli(*args):
  return subprocess.run(["mattstash", *args], capture_output=True, text=True)

def test_list_exits_zero():
  assert run_cli("list").returncode == 0
```