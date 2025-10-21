import asn1
import base64
import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone
from packaging.version import Version

PIN_POLICY = {"01": "never", "02": "once", "03": "always"}

TOUCH_POLICY = {"01": "never", "02": "always", "03": "cached"}

logger = logging.getLogger()


class yubikey_embedded_attestation:
    def __init__(self, config):
        self.config = config

    def validate(self, req):
        logger.debug("Validating with yubikey_embedded_attestation plugin")
        pub_key = req.x509CertificateRequest.publicKey
        pub_alg = req.x509CertificateRequest.publicKeyAlgorithm
        extensions = req.x509CertificateRequest.extensions

        attestation_cert = None
        intermediate_cert = None
        with open(self.config.yubikey_attestation_root, "rb") as file:
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

        if attestation_cert is None:
            logger.error("CSR does not include an attestation certificate")
            return False

        if intermediate_cert is None:
            logger.error("CSR does not include an intermediate attestation certificate")
            return False

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

        firmware_version = serial_number = pin_policy = touch_policy = None
        # https://docs.yubico.com/hardware/oid/webdocs.pdf
        for ext in attestation_cert.extensions:
            if ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.3":
                # Decode Firmware Version
                firmware_version = "%d.%d.%d" % tuple(ext.value.value[:3])
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.7":
                # Decode Serial Number
                decoder = asn1.Decoder()
                decoder.start(ext.value.value)
                _, serial_number = decoder.read()
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.8":
                # Decode Pin Policy and Touch Policy
                pin_policy = bytes.hex(ext.value.value[:1])
                pin_policy_value = PIN_POLICY.get(pin_policy)
                touch_policy = bytes.hex(ext.value.value[1:2])
                touch_policy_value = TOUCH_POLICY.get(touch_policy)

        if firmware_version is None:
            logger.error(f"Unknown firmware version")
            return False
        elif self.config.yubikey_min_version is None:
            logger.debug("No minimal firmware version required")
            pass
        elif Version(firmware_version) < Version(self.config.yubikey_min_version):
            logger.error(
                f"Yubikey version {firmware_version} is below required version ({self.config.yubikey_min_version})"
            )
            return False
        else:
            logger.debug(f"Yubikey version {firmware_version} is allowed")

        if serial_number is None:
            logger.error(f"Unknown serial number")
            return False
        elif len(self.config.yubikey_allowed_serials) < 1:
            logger.debug("No serial filtering configured")
            pass
        elif serial_number not in self.config.yubikey_allowed_serials:
            logger.error(f"Yubikey S/N {serial_number} is not allowed")
            return False
        else:
            logger.debug(f"Yubikey S/N {serial_number} is allowed")

        if pin_policy_value is None:
            logger.error(f"Unknown PIN policy")
            return False
        elif not getattr(self.config.yubikey_pin_policies, pin_policy_value):
            logger.error(
                f"PIN policy “{pin_policy_value}” ({pin_policy}) is not allowed"
            )
            return False
        else:
            logger.debug(f"PIN policy “{pin_policy_value}” ({pin_policy}) is allowed")

        if pin_policy_value is None:
            logger.error(f"Unknown touch policy")
            return False
        elif not getattr(self.config.yubikey_touch_policies, touch_policy_value):
            logger.error(
                f"Touch policy “{touch_policy_value}” ({touch_policy}) is not allowed"
            )
            return False
        else:
            logger.debug(
                f"Touch policy “{touch_policy_value}” ({touch_policy}) is allowed"
            )

        return True
