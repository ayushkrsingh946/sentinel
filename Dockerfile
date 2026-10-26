FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY sentinel/ sentinel/
COPY benchmark/ benchmark/
COPY sentinel.config.json .
COPY sentinel.scope.yml .
COPY sentinel.policy.yml .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pydantic matplotlib pytest && \
    pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["sentinel", "--help"]
