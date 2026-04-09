"""
Properties File Loader for LLMForge

Handles loading locale-specific properties files (e.g., messages_us.properties).
Currently supports US locale, with structure for easy expansion to other locales.
"""

from pathlib import Path
from typing import Dict, Optional
import configparser


class PropertiesLoader:
    """
    Loads and caches properties from locale-specific files.
    
    Properties files are stored as .properties files in the locale directory.
    Format: key=value (one per line)
    """
    
    _cache: Dict[str, Dict[str, str]] = {}
    
    @classmethod
    def _get_properties_dir(cls) -> Path:
        """Get the directory where properties files are stored."""
        # Navigate from framework module to project root, then to locale
        return Path(__file__).parent.parent.parent / "locale"
    
    @classmethod
    def _get_properties_file(cls, locale: str = "us") -> Path:
        """
        Get the path to the properties file for a given locale.
        
        Args:
            locale: Locale code (e.g., "us", "fr", "es")
            
        Returns:
            Path to the properties file
        """
        props_dir = cls._get_properties_dir()
        return props_dir / f"messages_{locale}.properties"
    
    @classmethod
    def load_properties(cls, locale: str = "us") -> Dict[str, str]:
        """
        Load properties from a properties file.
        
        Caches the loaded properties to avoid repeated file reads.
        
        Args:
            locale: Locale code (default: "us")
            
        Returns:
            Dictionary of key-value pairs from the properties file
            
        Raises:
            FileNotFoundError: If the properties file doesn't exist
        """
        # Return cached properties if available
        if locale in cls._cache:
            return cls._cache[locale]
        
        props_file = cls._get_properties_file(locale)
        
        if not props_file.exists():
            raise FileNotFoundError(
                f"Properties file not found: {props_file}\n"
                f"Expected file: {props_file.name}"
            )
        
        # Read properties file
        properties = {}
        with open(props_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                
                # Parse key=value
                if "=" in line:
                    key, value = line.split("=", 1)
                    properties[key.strip()] = value.strip()
        
        # Cache the properties
        cls._cache[locale] = properties
        return properties
    
    @classmethod
    def get_property(
        cls, 
        key: str, 
        locale: str = "us",
        default: Optional[str] = None
    ) -> str:
        """
        Get a single property value by key.
        
        Args:
            key: Property key
            locale: Locale code (default: "us")
            default: Default value if key not found
            
        Returns:
            Property value or default
        """
        properties = cls.load_properties(locale)
        return properties.get(key, default or key)
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear the properties cache."""
        cls._cache.clear()
