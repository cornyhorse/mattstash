"""
mattstash.cli.handlers.setup
----------------------------
Handler for the setup command.
"""

import os
from argparse import Namespace

from ...core.bootstrap import DatabaseBootstrapper
from ...models.config import config
from .base import BaseHandler


class SetupHandler(BaseHandler):
    """Handler for the setup command."""

    def handle(self, args: Namespace) -> int:
        """Handle the setup command."""
        try:
            # Determine the database path
            db_path = os.path.expanduser(args.path or config.default_db_path)
            db_dir = os.path.dirname(db_path) or "."
            sidecar_path = os.path.join(db_dir, config.sidecar_basename)

            # Check if files already exist
            db_exists = os.path.exists(db_path)
            sidecar_exists = os.path.exists(sidecar_path)

            if (db_exists or sidecar_exists) and not args.force:
                existing_files = []
                if db_exists:
                    existing_files.append(f"Database: {db_path}")
                if sidecar_exists:
                    existing_files.append(f"Sidecar: {sidecar_path}")

                self.error("Setup aborted - files already exist:")
                for file_info in existing_files:
                    print(f"  {file_info}")
                self.error("Use --force to overwrite existing files")
                return 1

            # Force bootstrap by creating a bootstrapper and calling the creation method directly
            bootstrapper = DatabaseBootstrapper(db_path)
            bootstrapper._create_database_and_sidecar(db_dir, sidecar_path)

            self.info("Setup complete!")
            print(f"  Database created: {db_path}")
            print(f"  Password file created: {sidecar_path}")
            return 0

        except Exception as e:
            self.error(f"Setup failed: {e}")
            return 1
