import yaml
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, List

class LLMSettings(BaseModel):
    provider: str
    # Ollama (uses `model` + `ollama_url`)
    model: str
    ollama_url: Optional[str] = None
    # Gemini
    gemini_model: Optional[str] = None
    gemini_api_key: Optional[str] = None
    # Groq
    groq_model: Optional[str] = None
    groq_api_key: Optional[str] = None
    # OpenAI
    openai_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    # Anthropic
    anthropic_model: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    # OpenRouter
    openrouter_model: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    max_tokens: int = 4096  # [#6] Max output tokens per LLM call (avoid truncated JSON/exploit)

class ApktoolSettings(BaseModel):
    path: Optional[str] = None

class JadxSettings(BaseModel):
    path: Optional[str] = None

class AnalysisSettings(BaseModel):
    generate_attack_surface_map: bool = False
    use_cross_reference_context: bool = True
    filter_mode: str = "llm_only" # static_only, llm_only, hybrid
    decompiler_mode: str = "apktool" # apktool, jadx, hybrid
    generate_exploit: bool = False
    scan_libraries: bool = False # [New V1.1.7]
    max_workers: int = 2          # [#6] Parallel deep-scan threads
    use_cache: bool = True        # [#4] Reuse identical LLM responses (resume-friendly)
    max_input_chars: int = 30000  # [#5] Truncate oversized file content before sending to LLM
 # Default to True for backward compatibility


class RulesSettings(BaseModel):
    # Fields are kept in alphabetical order — this is the order `dlh.py list-rules` prints.
    biometric_bypass: bool
    deeplink_hijack: bool
    deeplink_logic_bypass: bool
    exported_components: bool
    fragment_injection: bool
    graphql_injection: bool
    hardcoded_secrets: bool
    hardcoded_secrets_xml: bool
    insecure_deserialization: bool
    insecure_file_permissions: bool
    insecure_random_number_generation: bool
    insecure_storage: bool
    insecure_webview: bool
    intent_spoofing: bool
    jetpack_compose_security: bool
    path_traversal: bool
    pending_intent_hijacking: bool
    sql_injection: bool
    strandhogg: bool
    universal_logic_flaw: bool
    unsafe_reflection: bool
    webview_deeplink: bool
    webview_file_access: bool
    webview_xss: bool
    zip_slip: bool

class Settings(BaseModel):
    llm: LLMSettings
    apktool: ApktoolSettings
    jadx: Optional[JadxSettings] = None
    analysis: AnalysisSettings
    rules: RulesSettings

def load_settings(profile: str = None) -> Settings:
    if profile:
        path = f"config/profiles/{profile}.yaml"
    else:
        path = "config/settings.yaml"
        
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return Settings(**data)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {path}")
        raise
    except ValidationError as e:
        print(f"Error: Invalid configuration in {path}:\n{e}")
        raise

if __name__ == "__main__":
    # Example usage:
    try:
        settings = load_settings()
        print("Settings loaded successfully!")
        print(settings.model_dump_json(indent=2))
    except Exception as e:
        print(f"Failed to load settings: {e}")
