import base64
import hashlib
import hmac
import logging
import os
import sys
from enum import Enum
from typing import Union

import asgi_correlation_id
import mariadb
from config import Settings, WebhookSettings
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi_utils.tasks import repeat_every
from models import ssh_cert, x509_cert
from prometheus_client import Gauge, make_asgi_app
from pydantic import BaseModel, ValidationError
from webhook import scep_challenge, ssh, x509


def configure_logging():
    console_handler = logging.StreamHandler()
    console_handler.addFilter(asgi_correlation_id.CorrelationIdFilter())
    logging.basicConfig(
        handlers=[console_handler],
        level=os.environ.get("STEP_CA_INSPECTOR_LOGLEVEL", logging.INFO),
        format="%(levelname)s [%(correlation_id)s] %(message)s",
    )


app = FastAPI(
    title="step-ca Inspector API",
    on_startup=[configure_logging],
    strict_content_type=False,
)
app.add_middleware(asgi_correlation_id.CorrelationIdMiddleware)

logger = logging.getLogger()

try:
    config = Settings()
except ValidationError as e:
    for error in e.errors():
        logger.error(
            f"Configuration error: {error['msg']}: {'.'.join(str(node) for node in error['loc'])}"
        )
    sys.exit(1)

try:
    db_pool = mariadb.ConnectionPool(
        pool_name="step_pool",
        pool_reset_connection=True,
        **dict(config.database),
    )
except Exception as e:
    print(f"Could not connect to database: {e}")
    sys.exit(1)


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


class x509AttestationData(BaseModel):
    permanentIdentifier: str


class x509Cert(BaseModel):
    serial: str
    subject: str
    san_names: list[sanName] = []
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

    extensions: Union[list[x509Extension], None] = None
    extraExtensions: Union[list[x509Extension], None] = None

    dnsNames: Union[list, None] = None
    emailAddresses: Union[list, None] = None
    ipAddresses: Union[list, None] = None
    uris: Union[list, None] = None


class sshCertificateRequest(BaseModel):
    publicKey: bytes
    type: str
    keyID: str
    principals: list[str]


class x5CCertificate(BaseModel):
    raw: bytes
    publicKey: bytes
    publicKeyAlgorithm: str
    notBefore: str
    notAfter: str


class webhookSCEPChallenge(BaseModel):
    provisionerName: str
    scepChallenge: str
    scepTransactionID: str
    x509CertificateRequest: x509CertificateRequest


class webhookX5cSSHCertificateRequest(BaseModel):
    sshCertificateRequest: sshCertificateRequest
    x5cCertificate: x5CCertificate
    authorizationPrincipal: str


class webhookx509CertificateRequest(BaseModel):
    # NOTE: provisionerName is missing from step-ca requests
    # provisionerName: str
    x509CertificateRequest: x509CertificateRequest


class webhookx509AcmeCertificateRequest(webhookx509CertificateRequest):
    attestationData: Union[x509AttestationData, None] = None


class sshCertType(str, Enum):
    HOST = "Host"
    USER = "User"


class sshCert(BaseModel):
    serial: str
    alg: str
    type: sshCertType
    key_id: str
    principals: list[str] = []
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
@repeat_every(seconds=15, raise_exceptions=False, logger=logger)
async def update_metrics():
    x509_certs = x509_cert.list(
        db_pool=db_pool, expired_max_days=config.metrics_cert_expired_max_days
    )
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

    ssh_certs = ssh_cert.list(
        db_pool=db_pool, expired_max_days=config.metrics_cert_expired_max_days
    )
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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc.errors()}")
    return JSONResponse(
        {"errors": exc.errors()}, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
    )


@app.get("/x509/certs", tags=["x509"], summary="Get a list of x509 certificates")
def list_x509_certs(
    sort_key: str = Query(enum=["not_after", "not_before"], default="not_after"),
    cert_status: list[certStatus] = Query(["Valid"]),
    cert_expired_max_days: int = 30,
    subject: str = None,
    san: str = None,
    provisioner: str = None,
    provisioner_type: list[provisionerType] = Query(list(provisionerType)),
) -> list[x509Cert]:
    certs = x509_cert.list(
        db_pool=db_pool, sort_key=sort_key, expired_max_days=cert_expired_max_days
    )
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
    cert = x509_cert.cert.from_serial(db_pool=db_pool, serial=serial)
    if cert is None:
        return None
    cert.status = getattr(certStatus, cert.status.name)
    return cert


@app.get("/ssh/certs", tags=["ssh"], summary="Get a list of SSH certificates")
def list_ssh_certs(
    sort_key: str = Query(enum=["not_after", "not_before"], default="not_after"),
    cert_type: list[sshCertType] = Query(["Host", "User"]),
    cert_status: list[certStatus] = Query(["Valid"]),
    cert_expired_max_days: int = 30,
    key: str = None,
    principal: str = None,
) -> list[sshCert]:
    certs = ssh_cert.list(
        db_pool=db_pool, sort_key=sort_key, expired_max_days=cert_expired_max_days
    )
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
    cert = ssh_cert.cert.from_serial(db_pool=db_pool, serial=serial)
    if cert is None:
        return None
    cert.type = getattr(sshCertType, cert.type.name)
    cert.status = getattr(certStatus, cert.status.name)
    return cert


async def webhook_validate(
    request: Request,
    x_smallstep_webhook_id: str = Header(),
    x_smallstep_signature: str = Header(),
) -> WebhookSettings:

    logger.debug(f"Received webhook request for webhook ID {x_smallstep_webhook_id}")

    webhook_config = next(
        (
            webhook
            for webhook in config.webhook_config
            if webhook.id == x_smallstep_webhook_id
        ),
        None,
    )

    if webhook_config is None:
        logger.error("Invalid webhook ID")
        raise HTTPException(status_code=400, detail="Invalid webhook ID")

    try:
        signing_secret = base64.b64decode(webhook_config.secret)
    except ValueError as e:
        logger.error("Misconfigured webhook secret")
        raise HTTPException(status_code=500) from e

    try:
        sig = bytes.fromhex(x_smallstep_signature)
    except ValueError as e:
        logger.error("Invalid X-Smallstep-Signature header")
        raise HTTPException(
            status_code=400, detail="Invalid X-Smallstep-Signature header"
        ) from e

    body = await request.body()

    h = hmac.new(signing_secret, body, hashlib.sha256)

    if not hmac.compare_digest(sig, h.digest()):
        logger.error("Invalid signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    return webhook_config


@app.post(
    "/webhook/scepchallenge", tags=["webhooks"], summary="Valiate a SCEP challenge"
)
def webhook_scepchallenge(
    req: webhookSCEPChallenge,
    webhook_config: dict = Depends(webhook_validate),
) -> webhookResponse:

    logger.info("Received SCEP challenge webhook request")

    if not hasattr(scep_challenge, webhook_config.plugin.name):
        logger.error("Invalid challenge plugin configured")
        raise HTTPException(status_code=500)

    validator = getattr(scep_challenge, webhook_config.plugin.name)(
        webhook_config.plugin
    )

    response = validator.validate(req)
    if response.allow:
        logger.info("Validator approved certificate request")
    else:
        logger.warning("Validator refused certificate request")

    return response


@app.post(
    "/webhook/oidc",
    tags=["webhooks"],
    summary="Valiate and enrich an OIDC certificate request",
)
async def webhook_oidc(
    req: webhookx509CertificateRequest,
    webhook_config: WebhookSettings = Depends(webhook_validate),
) -> webhookResponse:

    logger.info("Received OIDC webhook request")

    if not hasattr(x509, webhook_config.plugin.name):
        logger.error("Invalid x509 plugin configured")
        raise HTTPException(status_code=500)

    validator = getattr(x509, webhook_config.plugin.name)(webhook_config.plugin)
    response = validator.validate(req)

    if response.allow:
        logger.info("Validator approved certificate request")
    else:
        logger.warning("Validator refused certificate request")

    return response


@app.post(
    "/webhook/ssh/x5c",
    tags=["webhooks"],
    summary="Validate and enrich an x5c certificate request",
)
async def webhook_ssh_x5c(
    req: webhookX5cSSHCertificateRequest,
    webhook_config: WebhookSettings = Depends(webhook_validate),
) -> webhookResponse:

    logger.info("Received SSH X5C webhook request")

    if not hasattr(ssh, webhook_config.plugin.name):
        logger.error("Invalid ssh plugin configured")
        raise HTTPException(status_code=500)

    validator = getattr(ssh, webhook_config.plugin.name)(webhook_config.plugin)
    response = validator.validate(req)

    if response.allow:
        logger.info("Validator approved certificate request")
    else:
        logger.warning("Validator refused certificate request")

    return response


@app.post(
    "/webhook/x509/acme",
    tags=["webhooks"],
    summary="Valiate and enrich an ACME X509 certificate request",
)
async def webhook_acme(
    req: webhookx509AcmeCertificateRequest,
    webhook_config: WebhookSettings = Depends(webhook_validate),
) -> webhookResponse:

    logger.info("Received ACME webhook request")

    if not hasattr(x509, webhook_config.plugin.name):
        logger.error("Invalid x509 plugin configured")
        raise HTTPException(status_code=500)

    validator = getattr(x509, webhook_config.plugin.name)(webhook_config.plugin)
    response = validator.validate(req)

    if response.allow:
        logger.info("Validator approved certificate request")
    else:
        logger.warning("Validator refused certificate request")

    return response
