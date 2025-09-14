import base64
import binascii
import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone

PIN_POLICY = {"01": "never", "02": "once per session", "03": "always"}

TOUCH_POLICY = {"01": "never", "02": "always", "03": "cached for 15s"}

logger = logging.getLogger()


class yubikey_embedded_attestation:
    config = {}

    def __init__(self, config):
        self.config = config

    def validate(self, req):
        logger.debug("Validating with yubikey_embedded_attestation plugin")
        pub_key = req.x509CertificateRequest.publicKey
        pub_alg = req.x509CertificateRequest.publicKeyAlgorithm
        extensions = req.x509CertificateRequest.extensions

        attestation_cert = None
        intermediate_cert = None
        with open(self.config.get("yubikey_attestation_root"), "rb") as file:
            root_cert = x509.load_pem_x509_certificate(file.read())

        for extension in extensions:
            if extension.id == "1.3.6.1.4.1.41482.3.1":
                attestation_cert = x509.load_der_x509_certificate(
                    base64.b64decode(extension.value)
                )

            elif extension.id == "1.3.6.1.4.1.41482.3.2":
                intermediate_cert = x509.load_der_x509_certificate(
                    base64.b64decode(extension.value)
                )

        try:
            intermediate_cert.public_key().verify(
                attestation_cert.signature,
                attestation_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            logger.debug("Valid intermediate attestation certificate signature")
        except Exception as e:
            logger.error(f"Invalid intermediate attestation certificate signature {e}")
            return False

        try:
            root_cert.public_key().verify(
                intermediate_cert.signature,
                intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            logger.debug("Valid root attestation certificate signature")
        except Exception as e:
            logger.error(f"Invalid root attestation certificate signature: {e}")
            return False

        current_time = datetime.now(timezone.utc)
        for cert in [attestation_cert, intermediate_cert, root_cert]:
            if cert.not_valid_before_utc <= current_time <= cert.not_valid_after_utc:
                logger.debug(f"Certificate {cert.subject.rfc4514_string()} is valid")
            else:
                logger.error(
                    f"Certificate {cert.subject.rfc4514_string()} is not valid"
                )
                return False

        csr_public_key_bytes = base64.b64decode(pub_key)
        attestation_public_key_bytes = attestation_cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if csr_public_key_bytes == attestation_public_key_bytes:
            logger.debug("CSR and attestation public keys match")
        else:
            logger.error("CSR and attestation public keys do not match")
            return False

        firmware_version = serial_number = pin_policy = touch_policy = "Not Found"
        # https://docs.yubico.com/hardware/oid/webdocs.pdf
        for ext in attestation_cert.extensions:
            if ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.3":
                # Decode Firmware Version
                ext_data = binascii.hexlify(ext.value.value).decode("utf-8")
                firmware_version = f"{int(ext_data[:2], 16)}.{int(ext_data[2:4], 16)}.{int(ext_data[4:6], 16)}"
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.7":
                # Decode Serial Number
                ext_data = ext.value.value
                # Assuming the first two bytes are not part of the serial number, skip them
                serial_number = int(binascii.hexlify(ext_data[2:]), 16)
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.8":
                # Decode Pin Policy and Touch Policy
                ext_data = binascii.hexlify(ext.value.value).decode("utf-8")
                pin_policy = ext_data[:2]
                pin_policy_str = PIN_POLICY.get(pin_policy, "Unknown")
                touch_policy = ext_data[2:4]
                touch_policy_str = TOUCH_POLICY.get(touch_policy, "Unknown")

        if "yubikey_allowed_serials" not in self.config:
            logger.debug("No serial filtering configured")
            pass
        elif serial_number not in self.config.get("yubikey_allowed_serials"):
            logger.error(f"Yubikey S/N {serial_number} is not allowed")
            return False
        else:
            logger.debug(f"Yubikey S/N {serial_number} is allowed")

        if "yubikey_allowed_pin_policy" not in self.config:
            logger.debug("No PIN policy configured")
            pass
        elif pin_policy not in self.config.get("yubikey_allowed_pin_policy"):
            logger.error(f"PIN policy “{pin_policy_str}” ({pin_policy}) is not allowed")
            return False
        else:
            logger.debug(f"PIN policy “{pin_policy_str}” ({pin_policy}) is allowed")

        if "yubikey_allowed_touch_policy" not in self.config:
            logger.debug("No touch policy configured")
            pass
        elif touch_policy not in self.config.get("yubikey_allowed_touch_policy"):
            logger.error(
                f"Touch policy “{touch_policy_str}” ({touch_policy}) is not allowed"
            )
            return False
        else:
            logger.debug(
                f"Touch policy “{touch_policy_str}” ({touch_policy}) is allowed"
            )

        return True
