FROM python:3.12-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sip.py .
COPY metrics/ ./metrics/
RUN adduser -D -H -S -u 10001 honeypot && mkdir -p /app/logs && chown honeypot /app/logs
USER honeypot
CMD ["python3", "sip.py"]
