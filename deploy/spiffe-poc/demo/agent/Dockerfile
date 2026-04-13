FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

USER 65534:65534

ENTRYPOINT ["python", "-m", "spiffe_agent.main"]
