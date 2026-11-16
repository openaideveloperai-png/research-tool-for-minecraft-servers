FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY frontend frontend
COPY exclude.example.txt /data/exclude.txt
ENV MCSEC_DB=/data/mcsec.sqlite3 MCSEC_HOST=0.0.0.0 MCSEC_PORT=8080 MCSEC_EXCLUDE_FILE=/data/exclude.txt
WORKDIR /app/backend
EXPOSE 8080
CMD ["python", "-m", "mcsec"]
