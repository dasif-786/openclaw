#!/usr/bin/env bash
# Run on the gateway host after DNS A record for DOMAIN points to this server's public IP.
# Requires: nginx site /etc/nginx/sites-available/openclaw proxying to 127.0.0.1:18789, ports 80/443 open.
set -euo pipefail
DOMAIN="${1:-openclaw.danish-freez.ip-ddns.com}"
sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
sudo nginx -t && sudo systemctl reload nginx
echo "Done. Open https://${DOMAIN}/ — ensure gateway.controlUi.allowedOrigins includes https://${DOMAIN}"
