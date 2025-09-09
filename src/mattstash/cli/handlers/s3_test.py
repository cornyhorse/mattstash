"""
mattstash.cli.handlers.s3_test
------------------------------
Handler for the s3-test command.
"""

from argparse import Namespace

from .base import BaseHandler
from ...module_functions import get_s3_client


class S3TestHandler(BaseHandler):
    """Handler for the s3-test command."""

    def handle(self, args: Namespace) -> int:
        """Handle the s3-test command."""
        try:
            client = get_s3_client(
                args.title,
                path=args.path,
                password=args.password,
                region=args.region,
                addressing=args.addressing,
                signature_version=args.signature_version,
                retries_max_attempts=args.retries_max_attempts,
                verbose=not args.quiet,
            )
        except Exception as e:
            if not args.quiet:
                self.error(f"failed to create S3 client: {e}")
            return 3

        if args.bucket:
            try:
                client.head_bucket(Bucket=args.bucket)
                if not args.quiet:
                    self.info(f"HeadBucket OK for {args.bucket}")
                return 0
            except Exception as e:
                if not args.quiet:
                    self.error(f"HeadBucket FAILED for {args.bucket}: {e}")
                return 4
        else:
            if not args.quiet:
                self.info("S3 client created successfully")
            return 0
