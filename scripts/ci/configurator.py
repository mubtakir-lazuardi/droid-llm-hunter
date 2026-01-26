import os
import sys
import logging
from typing import Dict, Any, Optional
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Constants
CONFIG_REL_PATH = "config/settings.yaml"
INPUT_PREFIX = "INPUT_"


def load_settings(config_path: str) -> Dict[str, Any]:
    """Loads the YAML configuration file securely."""
    if not os.path.exists(config_path):
        logger.warning(
            f"Configuration file not found at {config_path}. Starting with empty settings."
        )
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration: {e}")
        sys.exit(1)
    except OSError as e:
        logger.error(f"Error reading configuration file: {e}")
        sys.exit(1)


def save_settings(config_path: str, settings: Dict[str, Any]) -> None:
    """Saves the settings dictionary to the YAML file."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(settings, f, default_flow_style=False)
        logger.info(f"Configuration successfully saved to {config_path}")
    except OSError as e:
        logger.error(f"Failed to save configuration: {e}")
        sys.exit(1)


def apply_llm_settings(settings: Dict[str, Any]) -> None:
    """Injects CI/CD environment variables into the settings."""
    provider = os.environ.get(f"{INPUT_PREFIX}PROVIDER")
    model = os.environ.get(f"{INPUT_PREFIX}MODEL")
    api_key = os.environ.get(f"{INPUT_PREFIX}API_KEY")

    if not provider:
        logger.warning(
            "No 'provider' input specified. Skipping LLM configuration update."
        )
        return

    # Ensure 'llm' section exists
    if "llm" not in settings:
        settings["llm"] = {}

    settings["llm"]["provider"] = provider
    logger.info(f"LLM Provider set to: {provider}")

    # Model Configuration Mapping
    # Maps provider names to their specific model configuration keys
    model_config_map = {
        "ollama": "model",
        "gemini": "gemini_model",
        "groq": "groq_model",
        "openai": "openai_model",
        "anthropic": "anthropic_model",
    }

    # API Key Configuration Mapping
    api_key_map = {
        "gemini": "api_key",
        "groq": "groq_api_key",
        "openai": "openai_api_key",
        "anthropic": "anthropic_api_key",
    }

    # Update Model
    if model:
        key = model_config_map.get(provider)
        if key:
            settings["llm"][key] = model
            logger.info(f"Model set to: {model} for provider {provider}")
        else:
            logger.warning(f"Unknown provider '{provider}' for model configuration.")

    # Update API Key
    if api_key:
        key = api_key_map.get(provider)
        if key:
            settings["llm"][key] = api_key
            logger.info("API Key injected successfully.")
        elif provider != "ollama":  # Ollama typically doesn't use API key
            logger.warning(f"No API key configuration known for provider '{provider}'.")


def main():
    """Main entry point for CI configuration."""
    logger.info("Starting Droid-LLM-Hunter CI Configurator...")

    # Resolve paths relative to this script: scripts/ci/configurator.py
    # Application root is two levels up: ../../
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app_root = os.path.dirname(os.path.dirname(base_dir))
    config_path = os.path.join(app_root, CONFIG_REL_PATH)

    logger.info(f"Loading configuration from: {config_path}")

    settings = load_settings(config_path)
    apply_llm_settings(settings)
    save_settings(config_path, settings)


if __name__ == "__main__":
    main()
