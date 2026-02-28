import os
from enum import Enum
from typing import Literal, Optional, Union

from pydantic import Field, field_validator
from pydantic_core import PydanticCustomError
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


class PluginSettings(BaseSettings):
    pass


class AcmeAllowedDevicesPluginSettings(BaseSettings):
    permanent_identifier: str
    organizational_unit: Union[str, None] = None


class AcmePluginSettings(PluginSettings):
    name: Literal["acme_da_static"]
    allowed_devices: list[AcmeAllowedDevicesPluginSettings] = []


class ChallengeStaticSCEPPluginSettings(BaseSettings):
    secret: str
    allowed_dns_names: list[str] = []
    allowed_email_addresses: list[str] = []
    allowed_ip_addresses: list[str] = []


class StaticSCEPPluginSettings(PluginSettings):
    name: Literal["scep_static"]
    challenges: list[ChallengeStaticSCEPPluginSettings]


class VaultAuthMethod(str, Enum):
    TOKEN = "token"
    APPROLE = "approle"


class VaultPluginSettings(PluginSettings):
    name: Literal["hashicorp_vault"]
    hvac_connection: dict = {}
    hvac_auth_method: VaultAuthMethod = VaultAuthMethod.TOKEN
    hvac_token: Optional[str] = None
    hvac_role_id: Optional[str] = None
    hvac_secret_id: Optional[str] = None
    hvac_engine: str
    hvac_secret_path: str = "%s"
    hvac_challenge_key: str = "challenge"
    hvac_allowed_dns_names_key: str = "allowed_dns_names"
    hvac_allowed_email_addresses_key: str = "allowed_email_addresses"
    hvac_allowed_ip_addresses_key: str = "allowed_ip_addresses"
    hvac_allowed_uris: str = "allowed_uris"


class AcmeVaultPluginSettings(PluginSettings):
    name: Literal["acme_da_hashicorp_vault"]
    hvac_connection: dict = {}
    hvac_auth_method: VaultAuthMethod = VaultAuthMethod.TOKEN
    hvac_token: Optional[str] = None
    hvac_role_id: Optional[str] = None
    hvac_secret_id: Optional[str] = None
    hvac_engine: str
    hvac_secret_path: str = "%s"
    hvac_challenge_key: str = "challenge"
    hvac_organizational_unit: str = "organizational_unit"


class YubikeyPinPolicySettings(BaseSettings):
    never: Optional[bool] = True
    once: Optional[bool] = True
    always: Optional[bool] = True


class YubikeyTouchPolicySettings(BaseSettings):
    never: Optional[bool] = True
    always: Optional[bool] = True
    cached: Optional[bool] = True


class YubikeyEmbeddedAttestationSettings(PluginSettings):
    name: Literal["yubikey_embedded_attestation"]
    yubikey_attestation_root: str
    yubikey_allowed_serials: list[int] = []
    yubikey_min_version: Optional[str] = None
    yubikey_pin_policies: Optional[YubikeyPinPolicySettings] = (
        YubikeyPinPolicySettings()
    )
    yubikey_touch_policies: Optional[YubikeyTouchPolicySettings] = (
        YubikeyTouchPolicySettings()
    )


class X5cSSHPluginSettings(PluginSettings):
    name: Literal["x5c_ssh_altnet"]


class WebhookSettings(BaseSettings):
    id: str
    secret: str
    plugin: Union[tuple(PluginSettings.__subclasses__())] = Field(discriminator="name")


class Settings(BaseSettings):
    database: DatabaseSettings
    metrics_cert_expired_max_days: Optional[int] = 30
    webhook_config: list[WebhookSettings]

    @field_validator("webhook_config", mode="after")
    @classmethod
    def check_webhook_uniqueness(
        cls, webhooks: list[WebhookSettings]
    ) -> list[WebhookSettings]:
        ids = [webhook.id for webhook in webhooks]
        if len(ids) != len(set(ids)):
            raise PydanticCustomError(
                "webhook_id_uniqueness", "Webhooks IDs must be unique"
            )
        return webhooks

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
