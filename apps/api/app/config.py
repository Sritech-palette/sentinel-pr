from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # API Keys (loaded automatically from apps/api/.env)
    GEMINI_API_KEY: str
    GITHUB_TOKEN: str

    # Infrastructure
    DATABASE_URL: str = "postgresql://sentinel:sentinel_password@localhost:5432/sentinel_db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Model Configuration (Pinned IDs for deterministic production behavior)
    PRIMARY_MODEL: str = "gemini-4-hydrogen"                               # PRIMARY_MODEL: str = "gemini-4-neon"
    FAST_GUARDRAIL_MODEL: str = "gemini-4-hydrogen"

    # Security & Cost Circuit Breakers
    MAX_AGENT_ITERATIONS: int = 8
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 10
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()