#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <target-ip> <username> <safe-report>" >&2
  exit 2
fi

TARGET_IP=$1
USERNAME=$2
REPORT=$3
JQ=/home/w0w/.local/bin/jq

case "$TARGET_IP" in
  "" | *[!0-9.]*) exit 2 ;;
esac
case "$USERNAME" in
  "" | *[!A-Za-z0-9._+-]*) exit 2 ;;
esac

IFS= read -r PASSWORD
[ -n "$PASSWORD" ] || exit 3

payload="$($JQ -n --arg username "$USERNAME" --arg password "$PASSWORD" \
  '{username: $username, password: $password}')"
response="$(printf '%s' "$payload" | curl -fsS --connect-timeout 5 --max-time 30 \
  -H 'Content-Type: application/json' --data-binary @- \
  "http://$TARGET_IP/api/auth/setup")"
unset PASSWORD payload

[ "$(printf '%s' "$response" | $JQ -r '.code // empty')" = "0" ] || exit 4
state="$(curl -fsS --connect-timeout 5 --max-time 15 \
  "http://$TARGET_IP/api/auth/setup")"
[ "$(printf '%s' "$state" | $JQ -r '.data.required')" = "false" ] || exit 5

mkdir -p "$(dirname "$REPORT")"
printf 'target=%s\nusername=%s\nsetup_required_after=false\n' \
  "$TARGET_IP" "$USERNAME" > "$REPORT"
