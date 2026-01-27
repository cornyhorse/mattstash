"""
mattstash.cli.handlers.config
------------------------------
Handler for config command.
"""

from typing import Any
from pathlib import Path
from .base import BaseHandler


class ConfigHandler(BaseHandler):
    """Handler for generating example configuration files."""

    def handle(self, args: Any) -> int:
        """
        Generate an example configuration file.
        
        Args:
            args: Command-line arguments
            
        Returns:
            Exit code (0 for success)
        """
        try:
            from ...utils.config_loader import create_example_config
        except ImportError:
            print("Error: Configuration file support requires PyYAML")
            print("Install with: pip install 'mattstash[config]'")
            return 1
        
        # Determine output path
        if args.output:
            output_path = Path(args.output).expanduser()
        else:
            output_path = Path.home() / ".config" / "mattstash" / "config.yml"
        
        # Check if file already exists
        if output_path.exists():
            response = input(f"File {output_path} already exists. Overwrite? [y/N]: ")
            if response.lower() not in ('y', 'yes'):
                print("Cancelled.")
                return 0
        
        # Create example config
        example = create_example_config(output_path)
        
        print(f"✓ Created example configuration at: {output_path}")
        print(f"\nEdit this file to customize your MattStash settings.")
        print(f"\nConfiguration priority:")
        print(f"  1. CLI arguments (highest)")
        print(f"  2. Environment variables")
        print(f"  3. Config file: {output_path}")
        print(f"  4. Default values (lowest)")
        
        return 0
