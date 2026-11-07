#!/bin/sh

set -u
umask 077
LC_ALL=C
export LC_ALL

BASE_URL="${NANOKVM_BRIDGE_BASE_URL:-http://127.0.0.1}"
API_PREFIX="${NANOKVM_BRIDGE_API_PREFIX:-/api/picoclaw}"
TIMEOUT_SECONDS="${NANOKVM_BRIDGE_TIMEOUT_SECONDS:-15}"
CONNECT_TIMEOUT_SECONDS="${NANOKVM_BRIDGE_CONNECT_TIMEOUT_SECONDS:-5}"
SCREENSHOT_WIDTH="${NANOKVM_BRIDGE_SCREENSHOT_WIDTH:-640}"
SCREENSHOT_QUALITY="${NANOKVM_BRIDGE_SCREENSHOT_QUALITY:-50}"
INTERNAL_TOKEN="${NANOKVM_BRIDGE_INTERNAL_TOKEN:-${NANOKVM_INTERNAL_TOKEN:-}}"
# Legacy overrides are consumed by this shell, never inherited by curl/tools.
unset NANOKVM_BRIDGE_INTERNAL_TOKEN NANOKVM_INTERNAL_TOKEN
INTERNAL_TOKEN_FILE="${NANOKVM_BRIDGE_INTERNAL_TOKEN_FILE:-/etc/kvm/.picoclaw_internal_token}"
SESSION_ID=""

json_escape() {
  printf '%s' "${1-}" | awk '
    BEGIN {
      first = 1
    }
    {
      gsub(/\\/, "\\\\")
      gsub(/"/, "\\\"")
      gsub(/\t/, "\\t")
      gsub(/\r/, "\\r")
      if (!first) {
        printf "\\n"
      }
      printf "%s", $0
      first = 0
    }
  '
}

trim_spaces() {
  printf '%s' "${1-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

json_error() {
  code="$(json_escape "${1-ERROR}")"
  message="$(json_escape "${2-unknown error}")"
  extra="${3-}"
  if [ -n "$extra" ]; then
    printf '{"ok":false,"code":"%s","message":"%s",%s}\n' "$code" "$message" "$extra" >&2
  else
    printf '{"ok":false,"code":"%s","message":"%s"}\n' "$code" "$message" >&2
  fi
}

die() {
  json_error "$1" "$2" "${3-}"
  exit 1
}

require_integer_range() {
  name="$1"
  value="$2"
  min="$3"
  max="$4"
  case "$value" in
    ''|*[!0-9]*) die "INVALID_ARGUMENT" "invalid $name" ;;
  esac
  case "$value" in
    0) ;;
    0*) die "INVALID_ARGUMENT" "invalid $name" ;;
  esac
  [ "${#value}" -le 6 ] || die "INVALID_ARGUMENT" "invalid $name"
  [ "$value" -ge "$min" ] 2>/dev/null && [ "$value" -le "$max" ] 2>/dev/null ||
    die "INVALID_ARGUMENT" "invalid $name"
}

require_number() {
  name="$1"
  value="$2"
  case "$value" in
    -*) digits="${value#-}" ;;
    *) digits="$value" ;;
  esac
  case "$digits" in
    ''|*[!0-9]*) die "INVALID_ARGUMENT" "invalid numeric $name" ;;
  esac
  case "$digits" in
    0) ;;
    0*) die "INVALID_ARGUMENT" "invalid numeric $name" ;;
  esac
  [ "${#digits}" -le 7 ] || die "INVALID_ARGUMENT" "invalid numeric $name"
  [ "$value" -ge -1000000 ] 2>/dev/null && [ "$value" -le 1000000 ] 2>/dev/null ||
    die "INVALID_ARGUMENT" "invalid numeric $name"
}

mktemp_file() {
  mktemp "/tmp/nanokvm-bridge.XXXXXX" 2>/dev/null || mktemp -t nanokvm-bridge
}

cleanup_file() {
  if [ -n "${1-}" ] && [ -f "$1" ]; then
    rm -f "$1"
  fi
}

prepare_control_url() {
  # Only this management endpoint is constrained; target HID text/URLs are not.
  case "$BASE_URL" in
    *[![:graph:]]*|*\\*|*\?*|*\#*)
      die "INVALID_ARGUMENT" "invalid bridge control base URL" ;;
  esac
  CONTROL_SCHEME="$(printf '%s' "${BASE_URL%%://*}" | tr '[:upper:]' '[:lower:]')"
  case "$CONTROL_SCHEME" in
    http) CONTROL_PORT=80 ;;
    https) CONTROL_PORT=443 ;;
    *) die "INVALID_ARGUMENT" "bridge control URL must use http or https" ;;
  esac
  case "$BASE_URL" in
    *://*) ;;
    *) die "INVALID_ARGUMENT" "invalid bridge control base URL" ;;
  esac
  CONTROL_REST="${BASE_URL#*://}"
  CONTROL_AUTHORITY="${CONTROL_REST%%/*}"
  CONTROL_PATH=""
  case "$CONTROL_REST" in
    */*) CONTROL_PATH="/${CONTROL_REST#*/}" ;;
  esac
  case "$CONTROL_AUTHORITY" in
    ''|*@*|*%*) die "INVALID_ARGUMENT" "bridge control URL must not contain userinfo or encoded authority" ;;
  esac
  CONTROL_EXPLICIT_PORT=""
  case "$CONTROL_AUTHORITY" in
    \[*\]*)
      CONTROL_HOST="${CONTROL_AUTHORITY#\[}"
      CONTROL_HOST="${CONTROL_HOST%%\]*}"
      case "$CONTROL_HOST" in
        ''|*[!0-9a-fA-F:.]*) die "INVALID_ARGUMENT" "invalid bridge IPv6 host" ;;
      esac
      case "$CONTROL_HOST" in
        *:*) ;;
        *) die "INVALID_ARGUMENT" "invalid bridge IPv6 host" ;;
      esac
      CONTROL_HOST="[$(printf '%s' "$CONTROL_HOST" | tr '[:upper:]' '[:lower:]')]"
      CONTROL_SUFFIX="${CONTROL_AUTHORITY#*\]}"
      case "$CONTROL_SUFFIX" in
        '') ;;
        :*) CONTROL_EXPLICIT_PORT="${CONTROL_SUFFIX#:}" ;;
        *) die "INVALID_ARGUMENT" "invalid bridge control authority" ;;
      esac
      ;;
    *)
      CONTROL_HOST="${CONTROL_AUTHORITY%%:*}"
      CONTROL_HOST="$(printf '%s' "$CONTROL_HOST" | tr '[:upper:]' '[:lower:]')"
      case "$CONTROL_HOST" in
        ''|*[!a-z0-9._-]*) die "INVALID_ARGUMENT" "invalid bridge control host" ;;
      esac
      case "$CONTROL_AUTHORITY" in
        *:*) CONTROL_EXPLICIT_PORT="${CONTROL_AUTHORITY#*:}" ;;
      esac
      ;;
  esac
  # Reject an explicitly empty port, too, without overflowing shell arithmetic.
  case "$CONTROL_AUTHORITY" in
    *:) die "INVALID_ARGUMENT" "invalid bridge control port" ;;
  esac
  if [ -n "$CONTROL_EXPLICIT_PORT" ]; then
    case "$CONTROL_EXPLICIT_PORT" in
      *[!0-9]*) die "INVALID_ARGUMENT" "invalid bridge control port" ;;
    esac
    while [ "${CONTROL_EXPLICIT_PORT#0}" != "$CONTROL_EXPLICIT_PORT" ]; do
      CONTROL_EXPLICIT_PORT="${CONTROL_EXPLICIT_PORT#0}"
    done
    [ -n "$CONTROL_EXPLICIT_PORT" ] && [ "${#CONTROL_EXPLICIT_PORT}" -le 5 ] &&
      [ "$CONTROL_EXPLICIT_PORT" -le 65535 ] || die "INVALID_ARGUMENT" "invalid bridge control port"
    CONTROL_PORT="$CONTROL_EXPLICIT_PORT"
    CONTROL_EXPLICIT_PORT=":$CONTROL_PORT"
  fi
  case "$API_PREFIX" in
    /*) ;;
    *) die "INVALID_ARGUMENT" "bridge API prefix must be an absolute path" ;;
  esac
  case "$API_PREFIX" in
    //*|*[![:graph:]]*|*\\*|*\?*|*\#*) die "INVALID_ARGUMENT" "invalid bridge API prefix" ;;
  esac
  CONTROL_LOOPBACK=0
  case "$CONTROL_HOST" in
    127.0.0.1|localhost|\[::1\]) CONTROL_LOOPBACK=1 ;;
  esac
  url="${CONTROL_SCHEME}://${CONTROL_HOST}${CONTROL_EXPLICIT_PORT}${CONTROL_PATH%/}${API_PREFIX}${1-}"
}

resolve_internal_token() {
  if [ -z "$INTERNAL_TOKEN" ] && [ -r "$INTERNAL_TOKEN_FILE" ]; then
    # Numeric byte validation rejects NUL and embedded whitespace before shell
    # command substitution can discard bytes. The file/decoded value is bounded.
    INTERNAL_TOKEN="$(head -c 1025 "$INTERNAL_TOKEN_FILE" 2>/dev/null | od -An -v -tu1 | awk '
      {
        for (i = 1; i <= NF; i++) {
          count++
          byte = $i + 0
          if (count > 1024) { bad = 1; exit 1 }
          if (byte == 9 || byte == 10 || byte == 11 || byte == 12 || byte == 13 || byte == 32) {
            if (started) trailing = 1
            continue
          }
          if (byte < 33 || byte > 126 || trailing || length(token) >= 256) { bad = 1; exit 1 }
          token = token sprintf("%c", byte)
          started = 1
        }
      }
      END {
        if (bad || !started) exit 1
        printf "%s", token
      }
    ')" || return 1
  fi
  [ -n "$INTERNAL_TOKEN" ] && [ "${#INTERNAL_TOKEN}" -le 256 ] || return 1
  case "$INTERNAL_TOKEN" in
    *[![:graph:]]*) return 1 ;;
  esac
}

run_curl() (
  # A subshell owns this short-lived private file on normal exit and signals.
  request_headers="$(mktemp_file)" || return 1
  trap 'cleanup_file "$request_headers"' 0
  trap 'exit 1' HUP INT TERM
  chmod 600 "$request_headers" || return 1
  if [ -n "$SESSION_ID" ]; then
    [ "${#SESSION_ID}" -le 256 ] || return 1
    case "$SESSION_ID" in
      *[![:graph:]]*) return 1 ;;
    esac
    printf 'X-PicoClaw-Session-ID: %s\n' "$SESSION_ID" >"$request_headers" || return 1
  fi
  if [ "$CONTROL_LOOPBACK" -eq 1 ]; then
    resolve_internal_token || return 1
    printf 'X-NanoKVM-Internal-Token: %s\n' "$INTERNAL_TOKEN" >>"$request_headers" || return 1
    if [ "$CONTROL_HOST" = "localhost" ]; then
      set -- --resolve "localhost:$CONTROL_PORT:127.0.0.1" "$@"
    fi
    set -- -k --noproxy '*' "$@"
  fi
  # Redirects, curlrc, URL globbing, DNS for localhost and loopback proxies must
  # not move a local capability to a different service. Remote TLS stays strict.
  curl --disable --proto '=http,https' --proto-redir '=http,https' \
    --max-redirs 0 --globoff -H "@$request_headers" "$@"
)

normalize_session_hint() {
  value="${1-}"
  case "$value" in
    pico:*)
      printf '%s' "${value#pico:}"
      return 0
      ;;
    session:*)
      printf '%s' "${value#session:}"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

consume_session_hint() {
  value="${1-}"
  normalized="$(normalize_session_hint "$value")" || return 1
  [ -n "$normalized" ] || return 1
  SESSION_ID="$normalized"
  return 0
}

consume_global_option() {
  key="${1-}"
  value="${2-}"

  case "$key" in
    --session-id)
      [ -n "$value" ] || die "INVALID_ARGUMENT" "missing value for --session-id"
      SESSION_ID="$value"
      return 0
      ;;
    --base-url)
      [ -n "$value" ] || die "INVALID_ARGUMENT" "missing value for --base-url"
      BASE_URL="$value"
      return 0
      ;;
    --timeout-seconds)
      [ -n "$value" ] || die "INVALID_ARGUMENT" "missing value for --timeout-seconds"
      TIMEOUT_SECONDS="$value"
      require_integer_range "timeout seconds" "$TIMEOUT_SECONDS" 1 3600
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

scan_session_hints() {
  for arg in "$@"; do
    if consume_session_hint "$arg"; then
      return 0
    fi
  done
  return 1
}

# Every command option takes a value. That value is payload (text to type, a
# key list, a URL), never a session hint or a global option, whatever it looks
# like; only a bare argument can be a hint.
scan_global_options() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --session-id|--base-url|--timeout-seconds)
        [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
        consume_global_option "$1" "$2"
        shift 2
        ;;
      --*)
        if [ "$#" -ge 2 ]; then
          shift 2
        else
          shift
        fi
        ;;
      *)
        if consume_session_hint "$1"; then
          shift
          continue
        fi
        shift
        ;;
    esac
  done
}

resolve_session() {
  if [ -n "$SESSION_ID" ]; then
    return 0
  fi

  for key in AI_SESSION_ID PICO_SESSION_ID SESSION_ID; do
    eval "value=\${$key:-}"
    if [ -n "${value:-}" ]; then
      SESSION_ID="$value"
      return 0
    fi
  done

  resolve_session_from_runtime
}

resolve_session_from_runtime() {
  prepare_control_url "/runtime/session"
  response_file="$(mktemp_file)" || return 1
  status="$(
    run_curl -sS \
      -X GET \
      --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
      -m "$TIMEOUT_SECONDS" \
      -o "$response_file" \
      -w '%{http_code}' \
      --url "$url" 2>/dev/null
  )"
  curl_exit=$?

  if [ "$curl_exit" -ne 0 ]; then
    cleanup_file "$response_file"
    return 1
  fi

  case "$status" in
    2??)
      ;;
    *)
      cleanup_file "$response_file"
      return 1
      ;;
  esac

  current_session="$(extract_json_string current_session "$response_file")"
  cleanup_file "$response_file"

  if [ -z "$current_session" ]; then
    return 1
  fi

  SESSION_ID="$current_session"
  return 0
}

require_session() {
  resolve_session || die \
    "SESSION_ID_MISSING" \
    "missing session_id; pass --session-id or export AI_SESSION_ID/PICO_SESSION_ID/SESSION_ID"
}

read_body_file() {
  if [ -f "$1" ]; then
    cat "$1"
  fi
}

body_snippet() {
  if [ -f "$1" ]; then
    head -c 400 "$1" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g'
  fi
}

json_ok() {
  grep -Eq '"code"[[:space:]]*:[[:space:]]*0([[:space:]]*[,}])'
}

extract_json_string() {
  key="$1"
  file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

csv_to_json_array() {
  input="$1"
  old_ifs="$IFS"
  IFS=','
  set -- $input
  IFS="$old_ifs"

  output=""
  first=1
  for item in "$@"; do
    trimmed="$(trim_spaces "$item")"
    if [ -z "$trimmed" ]; then
      continue
    fi
    escaped="$(json_escape "$trimmed")"
    if [ "$first" -eq 1 ]; then
      output="\"$escaped\""
      first=0
    else
      output="$output,\"$escaped\""
    fi
  done

  printf '[%s]' "$output"
}

request_json() {
  method="$1"
  endpoint="$2"
  body="${3-}"
  prepare_control_url "$endpoint"
  response_file="$(mktemp_file)" || die "TEMPFILE_FAILED" "failed to create temporary response file"

  if [ "$method" = "GET" ]; then
    status="$(
      run_curl -sS \
        -X GET \
        --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
        -m "$TIMEOUT_SECONDS" \
        -o "$response_file" \
        -w '%{http_code}' \
        --url "$url"
    )"
  else
    status="$(
      run_curl -sS \
        -X "$method" \
        --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
        -m "$TIMEOUT_SECONDS" \
        -H "Content-Type: application/json" \
        --data "$body" \
        -o "$response_file" \
        -w '%{http_code}' \
        --url "$url"
    )"
  fi
  curl_exit=$?

  if [ "$curl_exit" -ne 0 ]; then
    cleanup_file "$response_file"
    die \
      "CURL_FAILED" \
      "curl request failed" \
      "\"url\":\"$(json_escape "$url")\",\"method\":\"$(json_escape "$method")\",\"curl_exit\":$curl_exit"
  fi

  case "$status" in
    2??)
      ;;
    *)
      snippet="$(body_snippet "$response_file")"
      cleanup_file "$response_file"
      die \
        "HTTP_ERROR" \
        "bridge api returned a non-2xx status" \
        "\"url\":\"$(json_escape "$url")\",\"method\":\"$(json_escape "$method")\",\"status\":$status,\"body\":\"$(json_escape "$snippet")\""
      ;;
  esac

  if ! json_ok <"$response_file"; then
    api_code="$(extract_json_string code "$response_file")"
    if [ -z "$api_code" ]; then
      api_code="API_ERROR"
    fi
    api_message="$(extract_json_string message "$response_file")"
    if [ -z "$api_message" ]; then
      api_message="$(extract_json_string msg "$response_file")"
    fi
    if [ -z "$api_message" ]; then
      api_message="bridge api returned an error payload"
    fi
    snippet="$(body_snippet "$response_file")"
    cleanup_file "$response_file"
    die \
      "$api_code" \
      "$api_message" \
      "\"url\":\"$(json_escape "$url")\",\"method\":\"$(json_escape "$method")\",\"status\":$status,\"body\":\"$(json_escape "$snippet")\""
  fi

  read_body_file "$response_file"
  cleanup_file "$response_file"
}

request_binary() {
  endpoint="$1"
  prepare_control_url "$endpoint"
  response_file="$(mktemp_file)" || die "TEMPFILE_FAILED" "failed to create temporary response file"
  header_file="$(mktemp_file)" || {
    cleanup_file "$response_file"
    die "TEMPFILE_FAILED" "failed to create temporary header file"
  }
  run_curl -sS \
    -X GET \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    -m "$TIMEOUT_SECONDS" \
    -D "$header_file" \
    -o "$response_file" \
    --url "$url"
  curl_exit=$?

  if [ "$curl_exit" -ne 0 ]; then
    cleanup_file "$response_file"
    cleanup_file "$header_file"
    die \
      "CURL_FAILED" \
      "curl request failed" \
      "\"url\":\"$(json_escape "$url")\",\"method\":\"GET\",\"curl_exit\":$curl_exit"
  fi

  status="$(awk 'toupper($1) ~ /^HTTP\// { code=$2 } END { print code }' "$header_file")"
  if [ -z "$status" ]; then
    cleanup_file "$response_file"
    cleanup_file "$header_file"
    die \
      "HTTP_ERROR" \
      "unable to parse response status" \
      "\"url\":\"$(json_escape "$url")\",\"method\":\"GET\""
  fi

  case "$status" in
    2??)
      cat "$response_file"
      cleanup_file "$response_file"
      cleanup_file "$header_file"
      ;;
    *)
      snippet="$(body_snippet "$response_file")"
      cleanup_file "$response_file"
      cleanup_file "$header_file"
      die \
        "HTTP_ERROR" \
        "bridge api returned a non-2xx status" \
        "\"url\":\"$(json_escape "$url")\",\"method\":\"GET\",\"status\":$status,\"body\":\"$(json_escape "$snippet")\""
      ;;
  esac
}

build_action_body() {
  action="$1"
  shift
  printf '{"action":"%s"' "$(json_escape "$action")"
  while [ "$#" -gt 0 ]; do
    key="$1"
    value="$2"
    kind="$3"
    shift 3
    case "$kind" in
      string)
        printf ',"%s":"%s"' "$key" "$(json_escape "$value")"
        ;;
      number)
        require_number "$key" "$value"
        printf ',"%s":%s' "$key" "$value"
        ;;
      raw)
        printf ',"%s":%s' "$key" "$value"
        ;;
      *)
        die "INVALID_ARGUMENT" "unsupported argument kind: $kind"
        ;;
    esac
  done
  printf '}'
}

join_csv_keys() {
  result=""
  while [ "$#" -gt 0 ]; do
    item="$(trim_spaces "$1")"
    shift
    [ -n "$item" ] || continue
    if [ -z "$result" ]; then
      result="$item"
    else
      result="$result,$item"
    fi
  done
  printf '%s' "$result"
}

build_macro_double_click_body() {
  x="$1"
  y="$2"
  button="$3"
  wait_ms="$4"
  require_number "x" "$x"
  require_number "y" "$y"
  require_number "wait_ms" "$wait_ms"
  printf '{"actions":[{"action":"move","x":%s,"y":%s},{"action":"click","x":%s,"y":%s,"button":"%s"},{"action":"wait","duration_ms":%s},{"action":"click","x":%s,"y":%s,"button":"%s"}]}' \
    "$x" "$y" "$x" "$y" "$(json_escape "$button")" "$wait_ms" "$x" "$y" "$(json_escape "$button")"
}

build_macro_type_enter_body() {
  text="$1"
  wait_ms="$2"
  require_number "wait_ms" "$wait_ms"
  printf '{"actions":[{"action":"type","text":"%s"},{"action":"wait","duration_ms":%s},{"action":"hotkey","keys":["ENTER"]}]}' \
    "$(json_escape "$text")" "$wait_ms"
}

build_macro_launch_app_body() {
  text="$1"
  launcher_keys="$2"
  launcher_wait_ms="$3"
  submit_wait_ms="$4"
  require_number "launcher_wait_ms" "$launcher_wait_ms"
  require_number "submit_wait_ms" "$submit_wait_ms"
  printf '{"actions":[{"action":"hotkey","keys":%s},{"action":"wait","duration_ms":%s},{"action":"type","text":"%s"},{"action":"wait","duration_ms":200},{"action":"hotkey","keys":["ENTER"]},{"action":"wait","duration_ms":%s}]}' \
    "$(csv_to_json_array "$launcher_keys")" "$launcher_wait_ms" "$(json_escape "$text")" "$submit_wait_ms"
}

build_macro_open_url_body() {
  url="$1"
  focus_keys="$2"
  focus_wait_ms="$3"
  submit_wait_ms="$4"
  require_number "focus_wait_ms" "$focus_wait_ms"
  require_number "submit_wait_ms" "$submit_wait_ms"
  printf '{"actions":[{"action":"hotkey","keys":%s},{"action":"wait","duration_ms":%s},{"action":"type","text":"%s"},{"action":"wait","duration_ms":200},{"action":"hotkey","keys":["ENTER"]},{"action":"wait","duration_ms":%s}]}' \
    "$(csv_to_json_array "$focus_keys")" "$focus_wait_ms" "$(json_escape "$url")" "$submit_wait_ms"
}

usage() {
  cat <<'EOF'
Usage:
  nanokvm-bridge.sh [--session-id SESSION_ID] [--base-url URL] [--timeout-seconds N] <command> [args]

Commands:
  screenshot [--format base64|jpeg]
  click --x N --y N [--button left|right|middle]
  move --x N --y N
  type --text TEXT
  hotkey --keys KEY1,KEY2
  scroll --direction up|down --amount N
  wait --duration-ms N
  drag --from-x N --from-y N --to-x N --to-y N
  double-click --x N --y N [--button left|right|middle] [--wait-ms N]
  type-enter --text TEXT [--wait-ms N]
  launch-app --text TEXT --launcher-shortcut KEY1,KEY2 [--launcher-wait-ms N] [--submit-wait-ms N]
  open-url --url URL --focus-shortcut KEY1,KEY2 [--focus-wait-ms N] [--submit-wait-ms N]
  actions-json '<json>'
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --session-id)
      [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --session-id"
      SESSION_ID="$2"
      shift 2
      ;;
    --base-url)
      [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --base-url"
      BASE_URL="$2"
      shift 2
      ;;
    --timeout-seconds)
      [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --timeout-seconds"
      TIMEOUT_SECONDS="$2"
      require_integer_range "timeout seconds" "$TIMEOUT_SECONDS" 1 3600
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if consume_session_hint "$1"; then
        shift
        continue
      fi
      break
      ;;
  esac
done

[ "$#" -gt 0 ] || {
  usage >&2
  exit 1
}

command="$1"
shift

scan_global_options "$@"

require_integer_range "timeout seconds" "$TIMEOUT_SECONDS" 1 3600
require_integer_range "connect timeout seconds" "$CONNECT_TIMEOUT_SECONDS" 1 300

require_session

case "$command" in
  screenshot)
    format="base64"
    width="$SCREENSHOT_WIDTH"
    quality="$SCREENSHOT_QUALITY"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --format)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --format"
          format="$2"
          shift 2
          ;;
        --width)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --width"
          width="$2"
          shift 2
          ;;
        --quality)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --quality"
          quality="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown screenshot argument: $1"
          ;;
      esac
    done

    require_integer_range "screenshot width" "$width" 1 8192
    require_integer_range "screenshot quality" "$quality" 1 100

    case "$format" in
      base64)
        request_json "GET" "/screenshot?format=base64&width=$width&quality=$quality"
        ;;
      jpeg)
        request_binary "/screenshot"
        ;;
      *)
        die "INVALID_ARGUMENT" "unsupported screenshot format: $format"
        ;;
    esac
    ;;

  click)
    x=""
    y=""
    button="left"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --x)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --x"
          x="$2"
          shift 2
          ;;
        --y)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --y"
          y="$2"
          shift 2
          ;;
        --button)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --button"
          button="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown click argument: $1"
          ;;
      esac
    done
    [ -n "$x" ] || die "INVALID_ARGUMENT" "click requires --x"
    [ -n "$y" ] || die "INVALID_ARGUMENT" "click requires --y"
    body="$(build_action_body "click" x "$x" number y "$y" number button "$button" string)"
    request_json "POST" "/actions" "$body"
    ;;

  move)
    x=""
    y=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --x)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --x"
          x="$2"
          shift 2
          ;;
        --y)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --y"
          y="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown move argument: $1"
          ;;
      esac
    done
    [ -n "$x" ] || die "INVALID_ARGUMENT" "move requires --x"
    [ -n "$y" ] || die "INVALID_ARGUMENT" "move requires --y"
    body="$(build_action_body "move" x "$x" number y "$y" number)"
    request_json "POST" "/actions" "$body"
    ;;

  type)
    text=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --text)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --text"
          text="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown type argument: $1"
          ;;
      esac
    done
    [ -n "$text" ] || die "INVALID_ARGUMENT" "type requires --text"
    body="$(build_action_body "type" text "$text" string)"
    request_json "POST" "/actions" "$body"
    ;;

  hotkey)
    keys=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --keys)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --keys"
          keys="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown hotkey argument: $1"
          ;;
      esac
    done
    [ -n "$keys" ] || die "INVALID_ARGUMENT" "hotkey requires --keys"
    body="$(build_action_body "hotkey" keys "$(csv_to_json_array "$keys")" raw)"
    request_json "POST" "/actions" "$body"
    ;;

  scroll)
    direction=""
    amount=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --direction)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --direction"
          direction="$2"
          shift 2
          ;;
        --amount)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --amount"
          amount="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown scroll argument: $1"
          ;;
      esac
    done
    [ -n "$direction" ] || die "INVALID_ARGUMENT" "scroll requires --direction"
    [ -n "$amount" ] || die "INVALID_ARGUMENT" "scroll requires --amount"
    body="$(build_action_body "scroll" direction "$direction" string amount "$amount" number)"
    request_json "POST" "/actions" "$body"
    ;;

  wait)
    duration_ms=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --duration-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --duration-ms"
          duration_ms="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown wait argument: $1"
          ;;
      esac
    done
    [ -n "$duration_ms" ] || die "INVALID_ARGUMENT" "wait requires --duration-ms"
    body="$(build_action_body "wait" duration_ms "$duration_ms" number)"
    request_json "POST" "/actions" "$body"
    ;;

  drag)
    from_x=""
    from_y=""
    to_x=""
    to_y=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --from-x)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --from-x"
          from_x="$2"
          shift 2
          ;;
        --from-y)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --from-y"
          from_y="$2"
          shift 2
          ;;
        --to-x)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --to-x"
          to_x="$2"
          shift 2
          ;;
        --to-y)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --to-y"
          to_y="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown drag argument: $1"
          ;;
      esac
    done
    [ -n "$from_x" ] || die "INVALID_ARGUMENT" "drag requires --from-x"
    [ -n "$from_y" ] || die "INVALID_ARGUMENT" "drag requires --from-y"
    [ -n "$to_x" ] || die "INVALID_ARGUMENT" "drag requires --to-x"
    [ -n "$to_y" ] || die "INVALID_ARGUMENT" "drag requires --to-y"
    body='{"action":"drag","from":{"x":'"$from_x"',"y":'"$from_y"'},"to":{"x":'"$to_x"',"y":'"$to_y"'}}'
    request_json "POST" "/actions" "$body"
    ;;

  double-click)
    x=""
    y=""
    button="left"
    wait_ms="120"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --x)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --x"
          x="$2"
          shift 2
          ;;
        --y)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --y"
          y="$2"
          shift 2
          ;;
        --button)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --button"
          button="$2"
          shift 2
          ;;
        --wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --wait-ms"
          wait_ms="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown double-click argument: $1"
          ;;
      esac
    done
    [ -n "$x" ] || die "INVALID_ARGUMENT" "double-click requires --x"
    [ -n "$y" ] || die "INVALID_ARGUMENT" "double-click requires --y"
    request_json "POST" "/actions" "$(build_macro_double_click_body "$x" "$y" "$button" "$wait_ms")"
    ;;

  type-enter)
    text=""
    wait_ms="150"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --text)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --text"
          text="$2"
          shift 2
          ;;
        --wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --wait-ms"
          wait_ms="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown type-enter argument: $1"
          ;;
      esac
    done
    [ -n "$text" ] || die "INVALID_ARGUMENT" "type-enter requires --text"
    request_json "POST" "/actions" "$(build_macro_type_enter_body "$text" "$wait_ms")"
    ;;

  launch-app)
    text=""
    launcher_shortcut=""
    launcher_wait_ms="400"
    submit_wait_ms="1800"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --text)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --text"
          text="$2"
          shift 2
          ;;
        --launcher-shortcut)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --launcher-shortcut"
          launcher_shortcut="$2"
          shift 2
          ;;
        --launcher-wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --launcher-wait-ms"
          launcher_wait_ms="$2"
          shift 2
          ;;
        --submit-wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --submit-wait-ms"
          submit_wait_ms="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown launch-app argument: $1"
          ;;
      esac
    done
    [ -n "$text" ] || die "INVALID_ARGUMENT" "launch-app requires --text"
    [ -n "$launcher_shortcut" ] || die "INVALID_ARGUMENT" "launch-app requires --launcher-shortcut"
    request_json "POST" "/actions" "$(build_macro_launch_app_body "$text" "$launcher_shortcut" "$launcher_wait_ms" "$submit_wait_ms")"
    ;;

  open-url)
    url=""
    focus_shortcut=""
    focus_wait_ms="250"
    submit_wait_ms="2000"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        --url)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --url"
          url="$2"
          shift 2
          ;;
        --focus-shortcut)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --focus-shortcut"
          focus_shortcut="$2"
          shift 2
          ;;
        --focus-wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --focus-wait-ms"
          focus_wait_ms="$2"
          shift 2
          ;;
        --submit-wait-ms)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for --submit-wait-ms"
          submit_wait_ms="$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          die "INVALID_ARGUMENT" "unknown open-url argument: $1"
          ;;
      esac
    done
    [ -n "$url" ] || die "INVALID_ARGUMENT" "open-url requires --url"
    [ -n "$focus_shortcut" ] || die "INVALID_ARGUMENT" "open-url requires --focus-shortcut"
    request_json "POST" "/actions" "$(build_macro_open_url_body "$url" "$focus_shortcut" "$focus_wait_ms" "$submit_wait_ms")"
    ;;

  actions-json)
    body=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --session-id|--base-url|--timeout-seconds)
          [ "$#" -ge 2 ] || die "INVALID_ARGUMENT" "missing value for $1"
          consume_global_option "$1" "$2"
          shift 2
          ;;
        *)
          if consume_session_hint "$1"; then
            shift
            continue
          fi
          body="$1"
          shift
          break
          ;;
      esac
    done
    [ -n "$body" ] || die "INVALID_ARGUMENT" "actions-json requires a JSON body"
    request_json "POST" "/actions" "$body"
    ;;

  *)
    die "INVALID_ARGUMENT" "unknown command: $command"
    ;;
esac
