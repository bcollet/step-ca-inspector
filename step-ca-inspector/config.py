import os
from typing import Optional

from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)


class DatabaseSettings(BaseSettings):
    host: str
    user: str
    password: str
    database: str
    ssl: bool = False
    ssl_verify_cert: bool = True
    ssl_ca: Optional[str] = None
    reconnect: bool = True
    pool_size: int = 5


class Settings(BaseSettings):
    database: DatabaseSettings
    metrics_cert_expired_max_days: Optional[int] = 30

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            EnvSettingsSource(
                settings_cls,
                env_nested_delimiter="__",
                case_sensitive=False,
                env_prefix="STEP_CA_INSPECTOR_",
            ),
            YamlConfigSettingsSource(
                settings_cls,
                yaml_file=os.environ.get("STEP_CA_INSPECTOR_CONFIGURATION"),
            ),
        )
