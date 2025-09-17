from fastapi import HTTPException
from fnmatch import fnmatch
from config import VaultAuthMethod
import hvac
import logging


logger = logging.getLogger()


class hashicorp_vault:
    def __init__(self, config):
        self.config = config
        self.client = hvac.Client(**self.config.hvac_connection)

        if self.config.hvac_auth_method == VaultAuthMethod.TOKEN:
            self.client.token = self.config.hvac_token
        elif self.config.hvac_auth_method == VaultAuthMethod.APPROLE:
            try:
                self.client.auth.approle.login(
                    role_id=self.config.hvac_role_id,
                    secret_id=self.config.hvac_secret_id,
                )
            except hvac.exceptions.VaultError as e:
                logger.error(f"HashiCorp Vault error: {e}")
                raise HTTPException(status_code=500)

        if not self.client.is_authenticated():
            logger.error("HashiCorp Vault client is not authenticated")
            raise HTTPException(status_code=500)

    def validate(self, req):
        logger.debug("Validating with hashicorp_vault plugin")
        cn = req.x509CertificateRequest.subject.get("commonName")

        try:
            secret = self.client.secrets.kv.v2.read_secret(
                path=self.config.hvac_secret_path % cn,
                mount_point=self.config.hvac_engine,
            )
        except hvac.exceptions.VaultError as e:
            logger.warning(f"HashiCorp Vault error: {e}")
            return False

        challenge = secret["data"]["data"].get(self.config.hvac_challenge_key)

        if req.scepChallenge != challenge:
            logger.error("SCEP challenge does not match")
            return False

        allowed_dns_names = secret["data"]["data"].get(
            self.config.hvac_allowed_dns_names_key, []
        ) + [cn]
        allowed_email_addresses = secret["data"]["data"].get(
            self.config.hvac_allowed_email_addresses_key, []
        )
        allowed_ip_addresses = secret["data"]["data"].get(
            self.config.hvac_allowed_ip_addresses_key, []
        )
        allowed_uris = secret["data"]["data"].get(self.config.hvac_allowed_uris, [])

        for dns_name in req.x509CertificateRequest.dnsNames or []:
            for allowed_dns_name in allowed_dns_names:
                if fnmatch(dns_name, allowed_dns_name):
                    logger.debug(f"DNS name {dns_name} is allowed")
                    break
            else:
                logger.error(f"DNS name {dns_name} is not allowed")
                return False

        for email_address in req.x509CertificateRequest.emailAddresses or []:
            if email_address not in allowed_email_addresses:
                logger.error(f"Email address {email_address} is not allowed")
                return False
            logger.debug(f"Email address {email_address} is allowed")

        for ip_address in req.x509CertificateRequest.ipAddresses or []:
            if ip_address not in allowed_ip_addresses:
                logger.error(f"IP address {ip_address} is not allowed")
                return False
            logger.debug(f"IP address {ip_address} is allowed")

        for uri in req.x509CertificateRequest.uris or []:
            if uri not in allowed_uris:
                logger.error(f"URI {uri} is not allowed")
                return False
            logger.debug(f"URI {uri} is allowed")

        return True


class scep_static:
    def __init__(self, config):
        self.config = config

    def validate(self, req):
        logger.debug("Validating with static plugin")

        challenge_config = next(
            (
                challenge
                for challenge in self.config.challenges
                if challenge.secret == req.scepChallenge
            ),
            None,
        )

        if challenge_config is None:
            logger.error("SCEP challenge does not match")
            return False

        cn = req.x509CertificateRequest.subject.get("commonName")

        for allowed_dns_name in challenge_config.allowed_dns_names:
            if fnmatch(cn, allowed_dns_name):
                logger.debug(f"Subject CN={cn} is allowed")
                break
        else:
            logger.error(f"Subject CN={cn} is not allowed")
            return False

        for dns_name in req.x509CertificateRequest.dnsNames or []:
            for allowed_dns_name in challenge_config.allowed_dns_names:
                if fnmatch(dns_name, allowed_dns_name):
                    logger.debug(f"DNS name {dns_name} is allowed")
                    break
            else:
                logger.error(f"DNS name {dns_name} is not allowed")
                return False

        for email_address in req.x509CertificateRequest.emailAddresses or []:
            if email_address not in challenge_config.allowed_email_addresses:
                logger.error(f"Email address {email_address} is not allowed")
                return False
            logger.debug(f"Email address {email_address} is allowed")

        for ip_address in req.x509CertificateRequest.ipAddresses or []:
            if ip_address not in challenge_config.allowed_ip_addresses:
                logger.error(f"IP address {ip_address} is not allowed")
                return False
            logger.debug(f"IP address {ip_address} is allowed")

        for uri in req.x509CertificateRequest.uris or []:
            if uri not in challenge_config.allowed_uris:
                logger.error(f"URI {uri} is not allowed")
                return False
            logger.debug(f"URI {uri} is allowed")

        return True
