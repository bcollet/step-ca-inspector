import base64
import logging

import asn1

# FIXME: Move webhookResponse elsewhere
import main
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger()


class x5c_ssh_altnet:
    def __init__(self, config):
        self.config = config

    def validate(self, req):
        logger.debug("Validating with x5c_ssh_altnet plugin")

        response = main.webhookResponse(allow=False)
        cert = x509.load_der_x509_certificate(base64.b64decode(req.x5cCertificate.raw))

        ssh_cert_allowed = False

        decoder = asn1.Decoder()

        for ext in cert.extensions:
            if ext.oid.dotted_string == "1.3.6.1.4.1.39196.3.2":
                decoder.start(ext.value.value)
                _, ssh_cert_allowed = decoder.read()

            if ext.oid.dotted_string == "1.3.6.1.4.1.39196.3.1":
                decoder.start(ext.value.value)
                _, principals = decoder.read()

        if not ssh_cert_allowed:
            logger.error("SSH Cert is not allowed for this certificate")
            return response

        ssh_pub_key_raw = base64.b64decode(req.sshCertificateRequest.publicKey)
        x5c_pub_key_bytes = base64.b64decode(req.x5cCertificate.publicKey)

        if len(ssh_pub_key_raw) < 4:
            logger.error("Invalid SSH public key")
            return response

        ssh_key_type_length = int.from_bytes(
            ssh_pub_key_raw[:4], byteorder="big", signed=False
        )

        ssh_pub_key_raw = ssh_pub_key_raw[4:]

        if len(ssh_pub_key_raw) < ssh_key_type_length:
            logger.error("Invalid SSH public key")
            return response

        ssh_pub_key = (
            ssh_pub_key_raw[:ssh_key_type_length]
            + b" "
            + req.sshCertificateRequest.publicKey
        )
        ssh_pub_key_obj = serialization.load_ssh_public_key(ssh_pub_key)
        ssh_pub_key_bytes = ssh_pub_key_obj.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if ssh_pub_key_bytes == x5c_pub_key_bytes:
            logger.debug("CSR and attestation public keys match")
        else:
            logger.error("CSR and attestation public keys do not match")
            return response

        response.allow = True
        response.data = {"principals": principals}
        return response
