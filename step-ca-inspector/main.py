from fastapi import FastAPI, HTTPException
from fastapi_utils.tasks import repeat_every
from prometheus_client import make_asgi_app, Gauge
from models import x509_cert, ssh_cert
from config import config
from pydantic import BaseModel
from typing import List, Union
from datetime import datetime
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


class provisioner(BaseModel):
    id: str
    name: str
    type: str


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
    status: str
    sha256: str
    sha1: str
    md5: str
    pub_key: str
    pub_alg: str
    sig_alg: str
    issuer: str
    pem: str


class sshCert(BaseModel):
    serial: str
    alg: str
    type: str
    key_id: str
    principals: List[str] = []
    not_after: int
    not_before: int
    revoked_at: Union[int, None] = None
    status: str
    signing_key: str
    signing_key_type: str
    signing_key_hash: str
    public_key: str
    public_key_type: str
    public_key_hash: str
    public_identity: str
    extensions: dict = {}


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
            "certificate_type": cert.type,
        }

        ssh_cert_not_after.labels(**labels).set(cert.not_after)
        ssh_cert_not_before.labels(**labels).set(cert.not_before)

        if cert.revoked_at is not None:
            ssh_cert_revoked_at.labels(**labels).set(cert.revoked_at)

        ssh_cert_status.labels(**labels).set(cert.status.value)


@app.get("/x509/certs", tags=["x509"])
def list_x509_certs(
    sort_key: str = "not_after", revoked: bool = False, expired: bool = False
) -> list[x509Cert]:
    certs = x509_cert.list(db, sort_key=sort_key)
    cert_list = []

    for cert in certs:
        if cert.status.value == x509_cert.status.EXPIRED and not expired:
            continue
        if cert.status.value == x509_cert.status.REVOKED and not revoked:
            continue

        cert.status = str(cert.status)
        cert_list.append(cert)

    return cert_list


@app.get("/x509/certs/{serial}", tags=["x509"])
def get_x509_cert(serial: str) -> Union[x509Cert, None]:
    cert = x509_cert.cert.from_serial(db, serial)
    if cert is None:
        return None
    cert.status = str(cert.status)
    return cert


@app.get("/ssh/certs", tags=["ssh"])
def list_ssh_certs(
    sort_key: str = "not_after", revoked: bool = False, expired: bool = False
) -> list[sshCert]:
    certs = ssh_cert.list(db, sort_key=sort_key)
    cert_list = []

    for cert in certs:
        if cert.status.value == ssh_cert.status.EXPIRED and not expired:
            continue
        if cert.status.value == ssh_cert.status.REVOKED and not revoked:
            continue

        cert.status = str(cert.status)
        cert_list.append(cert)

    return cert_list


@app.get("/ssh/certs/{serial}", tags=["ssh"])
def get_ssh_cert(serial: str) -> Union[sshCert, None]:
    cert = ssh_cert.cert.from_serial(db, serial)
    if cert is None:
        return None
    cert.status = str(cert.status)
    return cert
