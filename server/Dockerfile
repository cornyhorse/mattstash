FROM python:3.11-slim

WORKDIR /app

# Install mattstash from PyPI (main branch version)
# and server dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server application code
COPY app/ ./app/

# Add a 'server' shim so `command: server` in docker-compose prints helpful
# instructions instead of failing with "executable not found".
RUN printf '#!/bin/sh\n\
echo ""\n\
echo "ERROR: Do not use command: server in docker-compose."\n\
echo ""\n\
echo "The MattStash server starts automatically via its default CMD."\n\
echo "Remove the '\''command'\'' key from your docker-compose service and"\n\
echo "make sure the port mapping is 8000:8000, for example:"\n\
echo ""\n\
echo "  mattstash:"\n\
echo "    image: ghcr.io/cornyhorse/mattstash:latest"\n\
echo "    environment:"\n\
echo "      MATTSTASH_DB_PATH: /data/mattstash.kdbx"\n\
echo "      KDBX_PASSWORD: <password>"\n\
echo "      MATTSTASH_API_KEY: <api-key>"\n\
echo "    volumes:"\n\
echo "      - /path/to/data:/data:ro"\n\
echo "    ports:"\n\
echo "      - '\''8000:8000'\''"\n\
echo ""\n\
exit 1\n' > /usr/local/bin/server && chmod +x /usr/local/bin/server

EXPOSE 8000
USER nobody

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
