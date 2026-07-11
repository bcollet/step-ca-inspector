import logging
import os
import sys
from enum import Enum
from typing import Union

import asgi_correlation_id
import mariadb
from config import Settings
from fastapi import FastAPI, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi_utils.tasks import repeat_every
from models import ssh_cert, x509_cert
from prometheus_client import Gauge, make_asgi_app
from pydantic import BaseModel, ValidationError


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
