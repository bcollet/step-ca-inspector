from fastapi import FastAPI, HTTPException, Header, Query, Request, Depends
from fastapi_utils.tasks import repeat_every
from prometheus_client import make_asgi_app, Gauge
from pydantic import BaseModel
from typing import List, Union
from datetime import datetime
from enum import Enum
from models import x509_cert, ssh_cert
from config import config
from webhook import scep_challenge
import base64
import hashlib
import hmac
import mariadb
import sys

config()

try:
    db = mariadb.connect(**config.database)
except Exception as e:
    print(f"Could not connect to database: {e}")
    sys.exit(1)


app = FastAPI(title="step-ca Inspector API")

x509_label_names = ["subject", "san", "serial", "provisioner", "provisioner_type"]
x509_cert_not_before = Gauge(
    "step_ca_x509_certificate_not_before_timestamp_seconds",
    "Certificate not valid before timestamp",
    x509_label_names,
)
x509_cert_not_after = Gauge(
    "step_ca_x509_certificate_not_after_timestamp_seconds",
    "Certificate not valid after timestamp",
    x509_label_names,
)
x509_cert_revoked_at = Gauge(
    "step_ca_x509_certificate_revoked_at_timestamp_seconds",
    "Certificate not valid after timestamp",
    x509_label_names,
)
x509_cert_status = Gauge(
    "step_ca_x509_certificate_status",
    "Certificate status",
    x509_label_names,
)

ssh_label_names = ["key_id", "principals", "serial", "certificate_type"]
ssh_cert_not_before = Gauge(
    "step_ca_ssh_certificate_not_before_timestamp_seconds",
    "Certificate not valid before timestamp",
    ssh_label_names,
)
ssh_cert_not_after = Gauge(
    "step_ca_ssh_certificate_not_after_timestamp_seconds",
    "Certificate not valid after timestamp",
    ssh_label_names,
)
ssh_cert_revoked_at = Gauge(
    "step_ca_ssh_certificate_revoked_at_timestamp_seconds",
    "Certificate not valid after timestamp",
    ssh_label_names,
)
ssh_cert_status = Gauge(
    "step_ca_ssh_certificate_status",
    "Certificate status",
    ssh_label_names,
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


class certStatus(str, Enum):
    REVOKED = "Revoked"
    EXPIRED = "Expired"
    VALID = "Valid"


class provisionerType(str, Enum):
    # https://github.com/smallstep/certificates/blob/938a4da5adf2d32f36ffd06922e5c66956dfff41/authority/provisioner/provisioner.go#L200-L223
    ACME = "ACME"
    AWS = "AWS"
    GCP = "GCP"
    JWK = "JWK"
    Nebula = "Nebula"
    OIDC = "OIDC"
    SCEP = "SCEP"
    SSHPOP = "SSHPOP"
    X5C = "X5C"
    K8sSA = "K8sSA"


class provisioner(BaseModel):
    id: str
    name: str
    type: provisionerType


class sanName(BaseModel):
    type: str
    value: str


class x509Cert(BaseModel):
    serial: str
    subject: str
    san_names: List[sanName] = []
    provisioner: provisioner
    not_after: int
    not_before: int
    revoked_at: Union[int, None] = None
    status: certStatus
    sha256: str
    sha1: str
    md5: str
    pub_key: str
    pub_alg: str
    sig_alg: str
    issuer: str
    pem: str


class x509Extension(BaseModel):
    id: str
    critical: bool
    value: str


# https://pkg.go.dev/crypto/x509#CertificateRequest
class x509CertificateRequest(BaseModel):
    version: int
    signature: Union[str, None] = None
    signatureAlgorithm: str

    publicKey: str
    publicKeyAlgorithm: str

    subject: dict

    extensions: Union[List[x509Extension], None] = None
    extraExtensions: Union[List[x509Extension], None] = None

    dnsNames: Union[list, None] = None
    emailAddresses: Union[list, None] = None
    ipAddresses: Union[list, None] = None
    uris: Union[list, None] = None


class x509SCEPChallenge(BaseModel):
    provisionerName: str
    scepChallenge: str
    scepTransactionID: str
    x509CertificateRequest: x509CertificateRequest


class sshCertType(str, Enum):
    HOST = "Host"
    USER = "User"


class sshCert(BaseModel):
    serial: str
    alg: str
    type: sshCertType
    key_id: str
    principals: List[str] = []
    not_after: int
    not_before: int
    revoked_at: Union[int, None] = None
    status: certStatus
    signing_key: str
    signing_key_type: str
    signing_key_hash: str
    public_key: str
    public_key_type: str
    public_key_hash: str
    public_identity: str
    extensions: dict = {}


class webhookResponse(BaseModel):
    allow: bool
    data: dict = {}


@app.on_event("startup")
@repeat_every(seconds=15, raise_exceptions=False)
async def update_metrics():
    x509_certs = x509_cert.list(db=db)
    for cert in x509_certs:
        labels = {
            "subject": cert.subject,
            "san": ",".join(f"{x['type']}:{x['value']}" for x in cert.san_names),
            "serial": cert.serial,
            "provisioner": cert.provisioner["name"],
            "provisioner_type": cert.provisioner["type"],
        }

        x509_cert_not_after.labels(**labels).set(cert.not_after)
        x509_cert_not_before.labels(**labels).set(cert.not_before)

        if cert.revoked_at is not None:
            x509_cert_revoked_at.labels(**labels).set(cert.revoked_at)

        x509_cert_status.labels(**labels).set(cert.status.value)

    ssh_certs = ssh_cert.list(db=db)
    for cert in ssh_certs:
        labels = {
            "principals": ",".join([x.decode() for x in cert.principals]),
            "serial": cert.serial,
            "key_id": cert.key_id.decode(),
            "certificate_type": getattr(sshCertType, cert.type.name).value,
        }

        ssh_cert_not_after.labels(**labels).set(cert.not_after)
        ssh_cert_not_before.labels(**labels).set(cert.not_before)

        if cert.revoked_at is not None:
            ssh_cert_revoked_at.labels(**labels).set(cert.revoked_at)

        ssh_cert_status.labels(**labels).set(cert.status.value)


@app.get("/x509/certs", tags=["x509"], summary="Get a list of x509 certificates")
def list_x509_certs(
    sort_key: str = Query(enum=["not_after", "not_before"], default="not_after"),
    cert_status: list[certStatus] = Query(["Valid"]),
    subject: str = None,
    san: str = None,
    provisioner: str = None,
    provisioner_type: list[provisionerType] = Query(list(provisionerType)),
) -> list[x509Cert]:
    certs = x509_cert.list(db, sort_key=sort_key)
    cert_list = []

    for cert in certs:
        if cert.status.name not in [item.name for item in cert_status]:
            continue
        if (
            provisioner is not None
            and provisioner.casefold() not in cert.provisioner["name"].casefold()
        ):
            continue
        if cert.provisioner["type"] not in [item.name for item in provisioner_type]:
            continue
        if subject is not None and subject.casefold() not in cert.subject.casefold():
            continue
        if san is not None:
            for cert_san_name in cert.san_names:
                if san.casefold() in cert_san_name["value"].casefold():
                    break
            else:
                continue

        cert.status = getattr(certStatus, cert.status.name)
        cert_list.append(cert)

    return cert_list


@app.get(
    "/x509/certs/{serial}", tags=["x509"], summary="Get details on an x509 certificate"
)
def get_x509_cert(serial: str) -> Union[x509Cert, None]:
    cert = x509_cert.cert.from_serial(db, serial)
    if cert is None:
        return None
    cert.status = getattr(certStatus, cert.status.name)
    return cert


@app.get("/ssh/certs", tags=["ssh"], summary="Get a list of SSH certificates")
def list_ssh_certs(
    sort_key: str = Query(enum=["not_after", "not_before"], default="not_after"),
    cert_type: list[sshCertType] = Query(["Host", "User"]),
    cert_status: list[certStatus] = Query(["Valid"]),
    key: str = None,
    principal: str = None,
) -> list[sshCert]:
    certs = ssh_cert.list(db, sort_key=sort_key)
    cert_list = []

    for cert in certs:
        if cert.status.name not in [item.name for item in cert_status]:
            continue
        if cert.type.name not in [item.name for item in cert_type]:
            continue
        if key is not None and key.casefold() not in str(cert.key_id).casefold():
            continue
        if principal is not None:
            for cert_principal in cert.principals:
                if principal.casefold() in str(cert_principal).casefold():
                    break
            else:
                continue

        cert.type = getattr(sshCertType, cert.type.name)
        cert.status = getattr(certStatus, cert.status.name)
        cert_list.append(cert)

    return cert_list


@app.get(
    "/ssh/certs/{serial}", tags=["ssh"], summary="Get details on an SSH certificate"
)
def get_ssh_cert(serial: str) -> Union[sshCert, None]:
    cert = ssh_cert.cert.from_serial(db, serial)
    if cert is None:
        return None
    cert.type = getattr(sshCertType, cert.type.name)
    cert.status = getattr(certStatus, cert.status.name)
    return cert


async def get_body(request: Request):
    return await request.body()


@app.post(
    "/webhook/scepchallenge", tags=["webhooks"], summary="Valiate a SCEP challenge"
)
def webhook_scepchallenge(
    req: x509SCEPChallenge,
    x_smallstep_webhook_id: str = Header(),
    x_smallstep_signature: str = Header(),
    body: bytes = Depends(get_body),
) -> webhookResponse:

    response = webhookResponse
    response.allow = False

    if not hasattr(config, "scep_webhook_config"):
        raise HTTPException(status_code=500, detail="No webhook configuration")

    if x_smallstep_webhook_id not in config.scep_webhook_config:
        raise HTTPException(status_code=400, detail="Invalid webhook ID")

    webhook_config = config.scep_webhook_config[x_smallstep_webhook_id]

    signing_secret = base64.b64decode(webhook_config["secret"])
    sig = bytes.fromhex(x_smallstep_signature)

    h = hmac.new(signing_secret, body, hashlib.sha256)

    if not hmac.compare_digest(sig, h.digest()):
        raise HTTPException(status_code=400, detail="Invalid signature")

    if not hasattr(scep_challenge, webhook_config.get("challenge_plugin", "static")):
        raise HTTPException(
            status_code=500, detail="Invalid challenge plugin configured"
        )

    validator = getattr(
        scep_challenge, webhook_config.get("challenge_plugin", "static")
    )(webhook_config.get("challenge_plugin_config", {}))

    if validator.validate(req):
        response.allow = True

    return response
