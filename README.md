# StepCA Inspector

StepCA Inspector is a companion app to
[step-ca](https://github.com/smallstep/certificates/) that exposes Prometheus
metrics about your CA and offer API endpoints to get x509 and SSH certificate
data by connecting directly to step-ca's database.

Currently only MariaDB/MySQL is supported, however adding support for
PostgreSQL should be easy.

A CLI client is also available
[here](https://git.alt.tf/bcollet/step-ca-inspector-client/).


## Quick start
```
cd step-ca-inspector
export STEP_CA_INSPECTOR_LOGLEVEL=DEBUG
export STEP_CA_INSPECTOR_CONFIGURATION=../config.yaml
uvicorn main:app --reload
```


## Prometheus metrics
Prometheus metrics are available at the `/metrics` endpoint and are refreshed
every 15 seconds.

### x509 certificates
#### Common labels

| Label              | Description                                                        | Example                                                           |
| ------------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `subject`          | String representation of the certificate subject                   | `CN=rns-router.senf.fr`                                           |
| `san`              | Comma-separated string representation of Subject Alternative Names | `DNS:home-virt3-kvm.senf.fr,DNS:home-virt3-kvm.sheep-barb.ts.net` |
| `serial`           | Certificate serial number                                          | `182912013496377385330799153517025252323`                         |
| `provisioner`      | StepCA provisioner used to request the certificate                 | `scep-network`                                                    |
| `provisioner_type` | StepCA provisioner type                                            | `SCEP`                                                            |

#### Metrics
| Metric                                                  | Type  | Description                            |
| ------------------------------------------------------- | ----- | -------------------------------------- |
| `step_ca_x509_certificate_not_before_timestamp_seconds` | Gauge | Certificate not valid before timestamp |
| `step_ca_x509_certificate_not_after_timestamp_seconds`  | Gauge | Certificate not valid after timestamp  |
| `step_ca_x509_certificate_revoked_at_timestamp_seconds` | Gauge | Certificate revoked at timestamp       |
| `step_ca_x509_certificate_status`                       | Gauge | Certificate status                     |

### SSH certificates
#### Common labels
| Label              | Description                             | Example                                                                 |
| ------------------ | --------------------------------------- | ----------------------------------------------------------------------- |
| `key_id`           | SSH key ID                              | `benjamin@example.com`                                                  |
| `principals`       | Comma-separated list of SSH principals  | `bcollet,benjamin@example.com,jumphost-user,console-user,network-admin` |
| `serial`           | SSH certificate serial number           | `10060537534291381716`                                                  |
| `certificate_type` | SSH certificate type (`Host` or `User`) | `User`                                                                  |

#### Metrics
| Metric                                                 | Type  | Description                            |
| ------------------------------------------------------ | ----- | -------------------------------------- |
| `step_ca_ssh_certificate_not_before_timestamp_seconds` | Gauge | Certificate not valid before timestamp |
| `step_ca_ssh_certificate_not_after_timestamp_seconds`  | Gauge | Certificate not valid after timestamp  |
| `step_ca_ssh_certificate_revoked_at_timestamp_seconds` | Gauge | Certificate revoked at timestamp       |
| `step_ca_ssh_certificate_status`                       | Gauge | Certificate status                     |

### Certificate status
| Value | Status  |
| ----- | ------- |
| `1`   | Revoked |
| `2`   | Expired |
| `3`   | Valid   |


## API endpoints
OpenAPI (formerly Swagger) documentation is available at `/docs`.
Alternatively, Redocly documentation is available at `/redoc`.
