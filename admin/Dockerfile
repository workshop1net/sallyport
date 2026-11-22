# The Sallyport admin site. Build context is the repository root (see compose.yaml);
# .dockerignore keeps .env, generated/ and the YAML configuration out of the image.
FROM python:3-slim
RUN pip install --no-cache-dir "psycopg[binary]" pyyaml cryptography
WORKDIR /app
COPY sallyport_core.py sallyport_admin.py /app/
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
CMD ["python", "-I", "/app/sallyport_admin.py"]
