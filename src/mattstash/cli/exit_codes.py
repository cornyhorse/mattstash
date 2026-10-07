"""
mattstash.cli.exit_codes
------------------------
Process exit codes used by the CLI (stable; scripts may rely on them).
"""

OK = 0
ERROR = 1  # generic failure / invalid input
NOT_FOUND = 2  # the requested secret does not exist
S3_CLIENT_FAILED = 3  # s3-test: could not build the client
S3_BUCKET_FAILED = 4  # s3-test: HeadBucket failed
DB_URL_FAILED = 5  # db-url: could not build the URL
DB_NOT_FOUND = 6  # the KeePass database file does not exist (run `mattstash setup`)
DB_ACCESS = 7  # database cannot be opened: wrong/missing password, corrupt file, lock timeout
WOULD_OVERWRITE = 8  # setup/backup refused to replace existing files
INTERRUPTED = 130  # Ctrl-C / SIGTERM / SIGHUP (128 + SIGINT, the shell convention)
COMMAND_NOT_EXECUTABLE = 126  # exec: the command exists but cannot be executed (same convention as env/xargs)
COMMAND_NOT_FOUND = 127  # exec: the command was not found (note: a command that runs keeps its own exit status)
