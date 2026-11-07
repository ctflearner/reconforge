"""ReconForge configuration — env-driven settings."""
from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "RF_", "env_file": ".env", "extra": "ignore"}

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8800
    debug: bool = False
    workers: int = 4

    # --- Paths ---
    data_dir: str = "data"
    uploads_dir: str = "data/uploads"
    reports_dir: str = "data/reports"
    results_dir: str = "data/results"
    decompiled_dir: str = "data/decompiled"
    screenshots_dir: str = "data/screenshots"
    db_url: str = "sqlite:///data/reconforge.db"

    # --- API Keys (all optional — modules degrade gracefully) ---
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    securitytrails_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    hunter_api_key: str = ""
    github_token: str = ""
    google_api_key: str = ""
    google_cse_id: str = ""
    abuseipdb_api_key: str = ""
    whoisxml_api_key: str = ""

    # --- Scan Defaults ---
    max_subdomains: int = 5000
    max_ports: int = 1000
    port_scan_timeout: int = 300
    http_timeout: int = 15
    max_concurrent_modules: int = 8
    max_upload_size_mb: int = 500
    screenshot_timeout: int = 30
    dns_wordlist: str = "wordlists/subdomains-top10k.txt"

    # --- Validation ---
    enable_validation: bool = True
    validation_retries: int = 2
    validation_timeout: int = 30

    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def ensure_dirs(self) -> None:
        for d in (
            self.uploads_dir,
            self.reports_dir,
            self.results_dir,
            self.decompiled_dir,
            self.screenshots_dir,
        ):
            Path(d).mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
