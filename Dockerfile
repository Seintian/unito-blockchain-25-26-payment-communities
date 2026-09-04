FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libssl-dev \
    libffi-dev \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency specifications
COPY pyproject.toml .

# Install dependencies
RUN uv venv /opt/venv && uv pip sync --python /opt/venv/bin/python pyproject.toml || uv pip install --python /opt/venv/bin/python -e .

# Copy project code
COPY . .
RUN uv pip install --python /opt/venv/bin/python -e .

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["payment-communities"]
CMD ["--help"]
