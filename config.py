import os
from typing import Set
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Discord Bot Token
    DISCORD_BOT_TOKEN: str = ""

    # OpenRouter API (Recomendado con saldo)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "google/gemini-2.5-flash"

    # Google Gemini API directo (Opcional)
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # Moderation Logging Channel
    MOD_LOG_CHANNEL_ID: int = 0

    # Whitelist & Trust Settings
    WHITELIST_ROLES: str = "admin,moderador,mod,core team,team,holder,vip,verified"
    ACCOUNT_SAFE_AGE_DAYS: int = 30

    # Confidence Thresholds
    THRESHOLD_LEVEL_1_ALERT: float = 0.70
    THRESHOLD_LEVEL_2_ACTION: float = 0.85

    # Safe Domains Whitelist (Avoids querying AI for standard official platforms)
    SAFE_DOMAINS: Set[str] = {
        "discord.com",
        "discord.gg",
        "twitter.com",
        "x.com",
        "github.com",
        "solana.com",
        "jup.ag",
        "helius.dev",
        "phantom.app",
        "solflare.com",
        "raydium.io",
        "birdeye.so",
        "dexscreener.com",
        "magicden.io",
        "tensor.trade",
    }

    @property
    def whitelisted_roles_set(self) -> Set[str]:
        return {r.strip().lower() for r in self.WHITELIST_ROLES.split(",") if r.strip()}

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
