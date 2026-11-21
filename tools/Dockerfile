# Tiny image that runs the ./sallyport helper without Python on the host.
# Built on demand by sallyport.cmd; the script itself is mounted from the repo.
FROM python:3-alpine
RUN pip install --no-cache-dir pyyaml && apk add --no-cache postgresql-client
ENV SALLYPORT_IN_CONTAINER=1
WORKDIR /work
ENTRYPOINT ["python", "-I", "/work/sallyport"]
