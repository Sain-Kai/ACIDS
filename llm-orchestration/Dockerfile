FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home --home-dir /home/sentinelmesh sentinelmesh
COPY --chown=sentinelmesh:sentinelmesh . .
USER 10001:10001
EXPOSE 8090
ENV GUNICORN_BIND=0.0.0.0:8090
CMD ["sh", "-c", "exec gunicorn --bind \"${GUNICORN_BIND}\" --workers 2 --threads 4 --timeout 180 app:app"]
