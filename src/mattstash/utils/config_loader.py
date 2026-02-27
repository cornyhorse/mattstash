"""
mattstash.utils.config_loader
------------------------------
Configuration file loading utilities.

Supports YAML configuration files from:
1. ~/.config/mattstash/config.yml
2. ~/.mattstash.yml
3. .mattstash.yml (current directory)

Priority: CLI args > Environment variables > Config file > Defaults
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


def load_yaml_config() -> Dict[str, Any]:
    """
    Load configuration from YAML file if it exists.
    
    Searches for configuration in the following order:
    1. ~/.config/mattstash/config.yml
    2. ~/.mattstash.yml  
    3. .mattstash.yml (current directory)
    
    Returns:
        Dictionary of configuration values, empty dict if no file found
        
    Example:
        >>> config = load_yaml_config()
        >>> db_path = config.get('database', {}).get('path')
    """
    config_paths = [
        Path.home() / ".config" / "mattstash" / "config.yml",
        Path.home() / ".mattstash.yml",
    ]
    
    for path in config_paths:
        if path.exists():
            try:
                return _load_yaml_file(path)
            except Exception as e:
                logger.warning(f"Failed to load config from {path}: {e}")
                continue
    
    return {}


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """
    Load and parse a YAML configuration file.
    
    Args:
        path: Path to YAML file
        
    Returns:
        Parsed configuration dictionary
        
    Raises:
        ImportError: If PyYAML is not installed
        Exception: If file cannot be parsed
    """
    try:
        import yaml
    except ImportError:
        logger.info("PyYAML not installed, config file support disabled")
        return {}
    
    logger.info(f"Loading configuration from {path}")
    
    with open(path, 'r') as f:
        config = yaml.safe_load(f) or {}
    
    return config


def merge_config(file_config: Dict[str, Any], env_config: Dict[str, Any], 
                 cli_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge configurations with proper precedence.
    
    Priority (highest to lowest):
    1. CLI arguments (cli_config)
    2. Environment variables (env_config)
    3. Config file (file_config)
    4. Defaults (handled by caller)
    
    Args:
        file_config: Configuration from file
        env_config: Configuration from environment variables
        cli_config: Configuration from CLI arguments
        
    Returns:
        Merged configuration dictionary
        
    Example:
        >>> file_cfg = {'database': {'path': '/path/from/file'}}
        >>> env_cfg = {}
        >>> cli_cfg = {'database': {'path': '/path/from/cli'}}
        >>> result = merge_config(file_cfg, env_cfg, cli_cfg)
        >>> result['database']['path']
        '/path/from/cli'
    """
    result: Dict[str, Any] = {}
    
    # Start with file config as base
    _deep_merge(result, file_config)
    
    # Override with environment config
    _deep_merge(result, env_config)
    
    # Override with CLI config (highest priority)
    _deep_merge(result, cli_config)
    
    return result


def _deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    """
    Deep merge source dictionary into target dictionary.
    
    Args:
        target: Target dictionary to merge into (modified in place)
        source: Source dictionary to merge from
    """
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def get_config_value(config: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    Get a nested configuration value with dot notation support.
    
    Args:
        config: Configuration dictionary
        *keys: Keys to traverse (e.g., 'database', 'path')
        default: Default value if key not found
        
    Returns:
        Configuration value or default
        
    Example:
        >>> config = {'database': {'path': '/path/to/db'}}
        >>> get_config_value(config, 'database', 'path')
        '/path/to/db'
        >>> get_config_value(config, 'missing', 'key', default='fallback')
        'fallback'
    """
    current = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def create_example_config(path: Optional[Path] = None) -> str:
    """
    Create an example configuration file.
    
    Args:
        path: Optional path to write the example config to
        
    Returns:
        Example configuration as YAML string
        
    Example:
        >>> example = create_example_config()
        >>> print(example)
    """
    example = """# MattStash Configuration File
# Priority: CLI args > Environment variables > Config file > Defaults

# Database settings
database:
  # Path to KeePass database file
  path: ~/.config/mattstash/mattstash.kdbx
  
  # Basename for sidecar password file
  # Full path will be: <db_directory>/<sidecar_basename>
  sidecar_basename: .password.txt

# Versioning settings
versioning:
  # Width for zero-padded version numbers (e.g., 10 = "0000000042")
  pad_width: 10

# Logging settings
logging:
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: INFO
  
  # Enable detailed logging for debugging
  verbose: false

# S3 client settings (for get_s3_client method)
s3:
  # Default AWS region
  region: us-east-1
  
  # S3 addressing style: "virtual" or "path"
  addressing: path
  
  # AWS signature version
  signature_version: s3v4
  
  # Maximum retry attempts
  retries: 10

# Cache settings (opt-in feature)
cache:
  # Enable credential caching (default: false)
  enabled: false
  
  # Cache TTL in seconds (default: 300 = 5 minutes)
  ttl: 300
"""
    
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(example)
        logger.info(f"Created example configuration at {path}")
    
    return example
