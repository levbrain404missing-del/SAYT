#!/bin/bash
# Полное удаление демо-стенда stub-auth: служба, блок в Caddyfile, код, база, пользователь.
#
# Запуск:
#   sudo SITE_HOST=reg.example.com SITE_PORT=443 bash scripts/uninstall.sh
#
# SITE_HOST / SITE_PORT должны совпадать с тем, что реально стоит в /etc/caddy/Caddyfile.
# Если блока с таким именем нет — скрипт скажет об этом и Caddyfile не тронет.
set -e

SITE_HOST="${SITE_HOST:?укажите SITE_HOST — домен сайта из Caddyfile}"
SITE_PORT="${SITE_PORT:-443}"
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
# Комментарий-маркер, по которому ищется начало блока (см. caddy/site.example.conf).
MARKER="${MARKER:-# ВРЕМЕННЫЙ демо-стенд регистрации (stub-auth)}"

echo "1/5 останавливаю службу"
systemctl disable --now stub-auth.service 2>/dev/null || true
rm -f /etc/systemd/system/stub-auth.service
systemctl daemon-reload

echo "2/5 убираю блок из $CADDYFILE"
cp -a "$CADDYFILE" "$CADDYFILE.bak-before-stub-auth-removal-$(date +%F-%H%M)"
SITE_HOST="$SITE_HOST" SITE_PORT="$SITE_PORT" CADDYFILE="$CADDYFILE" MARKER="$MARKER" python3 - <<'PY'
import os
p = os.environ['CADDYFILE']
host, port, marker = os.environ['SITE_HOST'], os.environ['SITE_PORT'], os.environ['MARKER']
s = open(p, encoding='utf-8').read()

start = s.find(marker)
if start == -1:
    print('   маркер блока не найден — возможно, уже удалён или домен другой')
    raise SystemExit(0)
# Отступаем назад до строки-рамки '# ===...', если она есть.
line_start = s.rfind('\n', 0, start) + 1
prev_nl = s.rfind('\n', 0, line_start - 1) + 1
if s[prev_nl:line_start].startswith('# ==='):
    line_start = prev_nl
start = line_start

# Конец блока — закрывающая '}' site-блока https://host:port, а НЕ строка redir
# внутри предшествующего http-блока (поэтому ищем именно '\nhttps://...{').
site = f'\nhttps://{host}:{port} {{'
site_at = s.find(site, start)
end = s.find('\n}\n', site_at) if site_at != -1 else -1
if end == -1:
    print(f'   не нашёл закрытие блока https://{host}:{port} — Caddyfile НЕ изменён')
    raise SystemExit(1)

open(p, 'w', encoding='utf-8').write(s[:start].rstrip('\n') + '\n' + s[end + 3:])
print('   блок удалён')
PY
caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null && echo "   конфиг валиден"
systemctl reload caddy && echo "   caddy перезагружен (без restart)"

echo "3/5 удаляю данные и код"
rm -rf /var/lib/stub-auth /opt/stub-auth

echo "4/5 удаляю системного пользователя"
userdel stubauth 2>/dev/null || true

echo "5/5 готово. Сертификат Let's Encrypt для $SITE_HOST останется"
echo "    в хранилище Caddy и истечёт сам (вреда нет)."
