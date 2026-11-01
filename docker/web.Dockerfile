FROM python:3.12-slim
WORKDIR /app
COPY web/requirements.txt ./web/requirements.txt
RUN pip install --no-cache-dir -r web/requirements.txt
COPY web/ ./web/
RUN useradd -r -u 10001 webapp && chown -R webapp /app
USER webapp
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "--timeout", "30", "--no-control-socket", "web.app:app"]
