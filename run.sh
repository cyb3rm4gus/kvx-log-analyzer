#!/usr/bin/env bash
# Start Log Analyzer and open it. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
URL="http://127.0.0.1:8090"

command -v docker >/dev/null 2>&1 || { echo "Docker is not installed or not on PATH." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example — fill in GH_TOKEN and IPQS_KEY, then run this again." >&2
  exit 1
fi
if ! grep -qE '^GH_TOKEN=.+' .env; then
  echo "GH_TOKEN is empty in .env — every Guardhouse call would be rejected." >&2; exit 1
fi

docker compose up -d --build

printf 'Waiting for loganalyzer'
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null --max-time 2 "$URL/healthz" 2>/dev/null; then
    echo " — ready."
    # Connectivity check from INSIDE the container (spec §6, ruling 6-b): either Guardhouse
    # answers, or the analyst fixes their VPN. Nothing else in this tool touches that.
    GH_URL=$(grep -E '^GH_API_URL=' .env | cut -d= -f2- || true)
    GH_URL=${GH_URL:-http://10.10.100.1:8080}
    if docker compose exec -T loganalyzer python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('$GH_URL/readyz', timeout=5).status == 200 else 1)" 2>/dev/null; then
      echo "Guardhouse readyz: OK ($GH_URL)"
    else
      echo "Guardhouse readyz: NOT reachable from the container ($GH_URL) — check your VPN before pasting uuids." >&2
    fi
    if   command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 &
    else echo "Open $URL in your browser."; fi
    exit 0
  fi
  printf '.'; sleep 1
done
echo; echo "Timed out waiting for the container. Recent logs:" >&2
docker compose logs --tail 50 loganalyzer >&2
exit 1
