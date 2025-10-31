import base64
import dateutil
import json
import mariadb
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from datetime import datetime, timedelta, timezone
from struct import unpack
from enum import Enum


class list:
    def __new__(cls, db_pool, sort_key=None, expired_max_days=30):
        cls.certs = []
        db = db_pool.get_connection()
        cur = db.cursor()
        cur.execute(
            """SELECT ssh_certs.nvalue AS cert,
                      revoked_ssh_certs.nvalue AS revoked
               FROM ssh_certs
               LEFT JOIN revoked_ssh_certs USING(nkey)"""
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
        (cert_raw, cert_revoked_raw) = cert

        size = unpack(">I", cert_raw[:4])[0] + 4
        alg = cert_raw[4:size]

        cert_pub_id = b" ".join([alg, base64.b64encode(cert_raw)])

        if cert_revoked_raw is not None:
            cert_revoked = json.loads(cert_revoked_raw)
        else:
            cert_revoked = None

        self.load(cert_pub_id, cert_revoked, alg)

    @classmethod
    def from_serial(cls, db_pool, serial):
        cert = cls.get_cert(cls, db_pool, serial)
        if cert is None:
            return None
        return cls(cert=cert)

    def load(self, cert_pub_id, cert_revoked, cert_alg):
        cert = serialization.load_ssh_public_identity(cert_pub_id)
        self.serial = str(cert.serial)
        self.alg = cert_alg
        self.type = cert.type
        self.key_id = cert.key_id
        self.principals = cert.valid_principals
        self.not_after = cert.valid_before
        self.not_before = cert.valid_after
        # TODO: Implement critical options parsing
        # cert.critical_options
        self.extensions = cert.extensions

        (self.signing_key, self.signing_key_type, self.signing_key_hash) = (
            self.get_public_key_params(cert.signature_key())
        )

        (self.public_key, self.public_key_type, self.public_key_hash) = (
            self.get_public_key_params(cert.public_key())
        )

        self.public_identity = cert.public_bytes()

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
            """SELECT ssh_certs.nvalue AS cert,
                      revoked_ssh_certs.nvalue AS revoked
               FROM ssh_certs
               LEFT JOIN revoked_ssh_certs USING(nkey)
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

    def get_public_key_params(self, public_key):
        if isinstance(public_key, asymmetric.ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
        elif isinstance(public_key, asymmetric.ed25519.Ed25519PublicKey):
            key_type = "ED25519"
        elif isinstance(public_key, asymmetric.rsa.RSAPublicKey):
            key_type = "RSA"

        key_str = public_key.public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )

        key_data = key_str.strip().split()[1]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(base64.b64decode(key_data))
        hash_sha256 = digest.finalize()
        key_hash = base64.b64encode(hash_sha256)

        return key_str, key_type, key_hash


class status(Enum):
    REVOKED = 1
    EXPIRED = 2
    VALID = 3
