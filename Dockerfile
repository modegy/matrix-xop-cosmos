FROM eclipse-temurin:17-jre-jammy
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 xop && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin xop \
    && mkdir -p /data/jobs && chown -R 10001:10001 /data
COPY engine/packer.jar /opt/xop/packer.jar
COPY engine/shell-files /opt/xop/shell-files
COPY api/server.py /opt/xop/server.py
USER 10001:10001
WORKDIR /data
EXPOSE 8761
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8761/health',timeout=3)" || exit 1
ENTRYPOINT ["python3", "-u", "/opt/xop/server.py"]
