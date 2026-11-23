FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    HOST=0.0.0.0 \
    PORT=5000

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 whois iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.runtime.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY server ./server
COPY main.py .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"

CMD ["python", "server/server.py"]
