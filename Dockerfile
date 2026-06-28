# Vouchsafe demo server (FastAPI) — for Railway / any container host.
# Railway injects $PORT; run.py binds it. Set AP_BASE_URL and AP_RP_ID in the host env:
#   AP_BASE_URL = https://vouchsafe.promptica.it
#   AP_RP_ID    = vouchsafe.promptica.it      (WebAuthn rpId must equal the served domain)
FROM python:3.12-slim

WORKDIR /app
COPY packages/python ./packages/python
COPY server ./server
RUN pip install --no-cache-dir -e "./packages/python[server]"

WORKDIR /app/server
ENV HOST=0.0.0.0
CMD ["python", "run.py"]
