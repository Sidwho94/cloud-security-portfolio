# ==========================================
# Multi-stage hardened, non-root Dockerfile
# ==========================================

# Stage 1: Build & Dependencies
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

# Install dependencies into wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Minimal Distroless / Hardened Runtime
FROM python:3.11-slim-bookworm AS runner

# Security hardening: Create non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

WORKDIR /app

# Copy only the installed dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY app.py .

# Fix ownership
RUN chown -R appuser:appgroup /app /home/appuser/.local

# Set environment
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

# Drop to non-root
USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python", "app.py"]
