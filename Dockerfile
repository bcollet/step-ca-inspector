FROM python:3.9

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./step-ca-inspector /app/step-ca-inspector

CMD ["fastapi", "run", "step-ca-inspector/main.py", "--port", "8080", "--proxy-headers"]
