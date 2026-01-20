import asn1
import binascii
import dateutil
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta, timezone
from enum import Enum


class list:
    def __new__(cls, db_pool, sort_key=None, expired_max_days=30):
        cls.certs = []
        db = db_pool.get_connection()
        cur = db.cursor()
        cur.execute(
            """SELECT x509_certs.nvalue AS cert,
                      x509_certs_data.nvalue AS data,
                      revoked_x509_certs.nvalue AS revoked
               FROM x509_certs
               INNER JOIN x509_certs_data USING(nkey)
               LEFT JOIN revoked_x509_certs USING(nkey)"""
        )

        expired_max_date = datetime.timestamp(
            datetime.now(timezone.utc).replace(microsecond=0)
            - timedelta(days=expired_max_days)
        )

        for result in cur:
            cert_object = cert(result)

            if cert_object.not_after < expired_max_date:
                continue

            cls.certs.append(cert_object)

        cur.close()
        db.commit()
        db.close()

        if sort_key is not None:
            cls.certs.sort(key=lambda item: getattr(item, sort_key))

        return cls.certs


class cert:
    def __init__(self, cert):
        (cert_der, cert_data_raw, cert_revoked_raw) = cert

        cert_data = json.loads(cert_data_raw)
        if cert_revoked_raw is not None:
            cert_revoked = json.loads(cert_revoked_raw)
        else:
            cert_revoked = None

        self.load(cert_der, cert_data, cert_revoked)

    @classmethod
    def from_serial(cls, db_pool, serial):
        cert = cls.get_cert(cls, db_pool, serial)
        if cert is None:
            return None
        return cls(cert=cert)

    def load(self, cert_der, cert_data, cert_revoked):
        cert = x509.load_der_x509_certificate(cert_der)

        self.pem = cert.public_bytes(serialization.Encoding.PEM)
        self.serial = str(cert.serial_number)
        self.sha256 = binascii.b2a_hex(cert.fingerprint(hashes.SHA256()))
        self.sha1 = binascii.b2a_hex(cert.fingerprint(hashes.SHA1()))
        self.md5 = binascii.b2a_hex(cert.fingerprint(hashes.MD5()))
        self.pub_key = cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.pub_alg = cert.public_key_algorithm_oid._name
        self.sig_alg = cert.signature_algorithm_oid._name
        self.issuer = cert.issuer.rfc4514_string()
        self.subject = cert.subject.rfc4514_string({x509.NameOID.EMAIL_ADDRESS: "E"})
        self.not_before = datetime.timestamp(
            cert.not_valid_before_utc.replace(microsecond=0)
        )
        self.not_after = datetime.timestamp(
            cert.not_valid_after_utc.replace(microsecond=0)
        )
        try:
            san_data = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            self.san_names = self.get_sans(san_data)
        except x509.extensions.ExtensionNotFound:
            self.san_names = []

        self.provisioner = cert_data.get("provisioner", None)

        if cert_revoked is not None:
            self.revoked_at = datetime.timestamp(
                dateutil.parser.isoparse(cert_revoked.get("RevokedAt")).replace(
                    microsecond=0
                )
            )
        else:
            self.revoked_at = None

        now_with_tz = datetime.timestamp(
            datetime.now(timezone.utc).replace(microsecond=0)
        )

        if self.revoked_at is not None and self.revoked_at < now_with_tz:
            self.status = status.REVOKED
        elif self.not_after < now_with_tz:
            self.status = status.EXPIRED
        else:
            self.status = status.VALID

    def get_cert(self, db_pool, cert_serial):
        db = db_pool.get_connection()
        cur = db.cursor()
        cur.execute(
            """SELECT x509_certs.nvalue AS cert,
                      x509_certs_data.nvalue AS data,
                      revoked_x509_certs.nvalue AS revoked
               FROM x509_certs
               INNER JOIN x509_certs_data USING(nkey)
               LEFT JOIN revoked_x509_certs USING(nkey)
               WHERE nkey=?""",
            (cert_serial,),
        )

        if cur.rowcount > 0:
            cert = cur.fetchone()
        else:
            cert = None

        cur.close()
        db.commit()
        db.close()
        return cert

    def get_sans(self, san_data):
        sans = []

        for san_value in san_data.value:
            san = {}
            if isinstance(san_value, x509.general_name.DNSName):
                san["type"] = "DNS"
            elif isinstance(san_value, x509.general_name.UniformResourceIdentifier):
                san["type"] = "URI"
            elif isinstance(san_value, x509.general_name.RFC822Name):
                san["type"] = "Email"
            elif isinstance(san_value, x509.general_name.IPAddress):
                san["type"] = "IP"
            elif isinstance(san_value, x509.general_name.DirectoryName):
                san["type"] = "DirectoryName"
            elif isinstance(san_value, x509.general_name.RegisteredID):
                san["type"] = "RegisteredID"
            elif isinstance(san_value, x509.general_name.OtherName):
                if san_value.type_id == x509.oid.OtherNameFormOID.PERMANENT_IDENTIFIER:
                    san["type"] = f"Other (Permanent Identifier)"
                    decoder = asn1.Decoder()
                    decoder.start(san_value.value)
                    _, permanent_identifier = decoder.read()
                    san["value"] = ", ".join(permanent_identifier)
                else:
                    san["type"] = f"Other ({san_value.type_id.dotted_string})"
                    san["value"] = "Unsupported"
            else:
                continue

            if not "value" in san:
                san["value"] = san_value.value
            sans.append(san)

        return sans


class status(Enum):
    REVOKED = 1
    EXPIRED = 2
    VALID = 3
