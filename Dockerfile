FROM --platform=linux/amd64 python:3.14-alpine

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN apk add --no-cache mariadb-connector-c mariadb-connector-c-dev gcc musl-dev python3-dev linux-headers && \
    pip install --no-cache-dir --upgrade -r /app/requirements.txt &&\
    pip cache purge && \
    apk del --rdepends --purge musl-dev gcc musl-dev python3-dev mariadb-connector-c-dev

COPY ./step-ca-inspector /app/step-ca-inspector

CMD ["fastapi", "run", "step-ca-inspector/main.py", "--port", "8080", "--proxy-headers"]
