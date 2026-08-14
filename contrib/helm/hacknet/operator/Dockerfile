FROM python:3.12-slim

ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Stacks Hacknet operator" \
      org.opencontainers.image.description="Namespaced reconciler for disposable StacksNetwork test environments" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"

WORKDIR /app
COPY controller.py /app/controller.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "/app/controller.py"]
