#!/usr/bin/env bash
# ============================================================================
#  ASM: установка лучшего бесплатного арсенала ИБ (весь топ мира, бесплатно)
# ============================================================================
#  Ставит в каталог ASM_TOOLS_DIR (по умолчанию <проект>/build/tools).
#
#  Работает в Linux, macOS и в Windows из Git Bash (MSYS/MINGW). В Windows
#  ставятся нативные Windows-сборки с суффиксом .exe — иначе движки просто не
#  запускаются, а оболочка MSYS не считает файл исполняемым.
#
#  Состав (всё — свободные лицензии, статические сборки, без root):
#    ProjectDiscovery : nuclei, naabu, subfinder, httpx, dnsx, tlsx, katana
#    Прочие           : ffuf, gau, amass, nikto, testssl.sh, trivy,
#                       gitleaks, trufflehog, osv-scanner, (nmap — Linux)
#    Python           : semgrep, wapiti, sqlite-vec (+ semgrep-rules)
#    Данные           : словари SecLists, шаблоны nuclei
#
#  Запуск:  bash bin/install-tools.sh                 (только отсутствующее)
#           bash bin/install-tools.sh --force         (перекачать всё)
#           bash bin/install-tools.sh --fast          (только ядро)
#           bash bin/install-tools.sh --tools         (без словарей)
#           bash bin/install-tools.sh --only=nuclei,dnsx,ffuf
#           bash bin/install-tools.sh --selftest      (только показать, какие
#                                                      сборки найдутся под эту ОС)
#           bash bin/install-tools.sh --only=naabu --npcap   (скачать Npcap и открыть мастер)
#           bash bin/install-tools.sh --only=nmap  --nmap    (скачать nmap; он ставит и Npcap)
#           bash bin/install-tools.sh --help
# ============================================================================
set -uo pipefail

usage() {
  cat <<'USAGE'
Установка арсенала ASM.

  bash bin/install-tools.sh                  только отсутствующее
  bash bin/install-tools.sh --force          перекачать всё
  bash bin/install-tools.sh --fast           только ядро
  bash bin/install-tools.sh --tools          без словарей
  bash bin/install-tools.sh --only=список    только перечисленное (nuclei,dnsx,ffuf)
  bash bin/install-tools.sh --selftest       показать, какие сборки найдутся под эту ОС

Установщики с графическим мастером (в PowerShell и в bash одинаково):
  bash bin/install-tools.sh --only=naabu --npcap     скачать Npcap и открыть мастер
  bash bin/install-tools.sh --only=nmap  --nmap      скачать nmap и открыть мастер
                                                     (его мастер ставит и Npcap)
  --npcap=ПУТЬ / --nmap=ПУТЬ                         взять свой файл установщика

Переменные окружения: ASM_TOOLS_DIR, ASM_NPCAP, ASM_NMAP, ASM_NMAP_EXE,
                      ASM_FORCE_PLATFORM, ASM_NMAP_VER, ASM_WITH_MODEL, GITHUB_TOKEN
USAGE
}

FORCE=0; SKIP_WORDS=0; FAST=0; SELFTEST=0; ONLY=""
for a in "$@"; do
  case "$a" in
    --force)  FORCE=1 ;;
    --fast)   FAST=1 ;;      # только ядро (разведка, порты, проверки по шаблонам)
    --tools)  SKIP_WORDS=1 ;;
    --selftest) SELFTEST=1 ;;
    --only=*) ONLY="${a#--only=}" ;;
    --npcap)   ASM_NPCAP="${ASM_NPCAP:-auto}" ;;   # скачать свежий установщик Npcap
    --npcap=*) ASM_NPCAP="${a#--npcap=}" ;;        # или взять указанный файл
    --nmap)    ASM_NMAP="${ASM_NMAP:-auto}" ;;     # скачать официальный setup.exe nmap
    --nmap=*)  ASM_NMAP="${a#--nmap=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $a (список: --help)"; exit 2 ;;
  esac
done

want() {  # want <имя> — ставить ли этот компонент (учитывает --only)
  [ -z "$ONLY" ] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; esac
  return 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ASM_TOOLS_DIR:-$ROOT/build/tools}"
BIN="$DIR/bin"; LIB="$DIR/lib"; TPL="$DIR/nuclei-templates"; WL="$ROOT/data/wordlists"
# Временные файлы держим ВНУТРИ каталога арсенала, а не в /tmp: в Windows из
# Git Bash путь /tmp существует только для самой оболочки, а сторонний python.exe
# его не понимает (отсюда и была ошибка FileNotFoundError: '/tmp/tpl.zip').
TMPD="$DIR/tmp"
mkdir -p "$BIN" "$LIB" "$WL" "$TMPD"

say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
miss() { printf '  \033[33m·\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
#  0. Платформа
# ---------------------------------------------------------------------------
UNAME_S="$(uname -s)"; UNAME_M="$(uname -m)"
case "$UNAME_S" in
  MINGW*|MSYS*|CYGWIN*) IS_WIN=1; GOOS=windows; OSNAME="Windows (Git Bash: $UNAME_S)" ;;
  Linux)                IS_WIN=0; GOOS=linux;   OSNAME="Linux" ;;
  Darwin)               IS_WIN=0; GOOS=darwin;  OSNAME="macOS" ;;
  *) echo "Неизвестная ОС: $UNAME_S"; exit 1 ;;
esac
# ASM_FORCE_PLATFORM позволяет проверить подбор сборок под другую ОС (--selftest)
if [ -n "${ASM_FORCE_PLATFORM:-}" ]; then
  GOOS="$ASM_FORCE_PLATFORM"
  if [ "$GOOS" = "windows" ]; then IS_WIN=1; else IS_WIN=0; fi
  OSNAME="$OSNAME (проверка под $GOOS)"
fi

case "$UNAME_M" in
  x86_64|amd64)   ARCH=amd64; GL_ARCH=x64 ;;
  aarch64|arm64)  ARCH=arm64; GL_ARCH=arm64 ;;
  i686|i386)      ARCH=386;   GL_ARCH=x32 ;;
  *) echo "Неизвестная архитектура: $UNAME_M"; exit 1 ;;
esac
EXE=""; [ "$IS_WIN" = "1" ] && EXE=".exe"

# Суффиксы ассетов, которые не совпадают со схемой <tool>_<os>_<arch>
case "$GOOS/$ARCH" in
  linux/amd64)   TRIVY_PAT='trivy_[0-9.]+_Linux-64bit\.tar\.gz$' ;;
  linux/arm64)   TRIVY_PAT='trivy_[0-9.]+_Linux-ARM64\.tar\.gz$' ;;
  windows/amd64) TRIVY_PAT='trivy_[0-9.]+_windows-64bit\.zip$' ;;
  darwin/amd64)  TRIVY_PAT='trivy_[0-9.]+_macOS-64bit\.tar\.gz$' ;;
  darwin/arm64)  TRIVY_PAT='trivy_[0-9.]+_macOS-ARM64\.tar\.gz$' ;;
  *)             TRIVY_PAT='trivy_[0-9.]+_[A-Za-z]+-(64bit|ARM64)\.(tar\.gz|zip)$' ;;
esac

# python: в Windows обычно нет python3 в PATH Git Bash, но есть python / py
PY=()
if command -v python3 >/dev/null 2>&1; then PY=(python3)
elif command -v python >/dev/null 2>&1; then PY=(python)
elif command -v py >/dev/null 2>&1; then PY=(py -3)
fi
PYNAME="${PY[*]:-нет}"

win_path() {  # win_path <путь> — путь в нотации Windows (для .cmd-обёрток)
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"
  else printf '%s\n' "$1" | sed -e 's|^/\([a-zA-Z]\)/|\U\1:/|' -e 's|/|\\|g'; fi
}

# Журнал того, что мы реально записывали на диск. Нужен, чтобы отличить
# «никогда не ставилось» от «поставилось, а потом файл пропал» (так ведёт себя
# антивирус: он удаляет nuclei/naabu/ffuf уже после того, как скрипт их проверил).
LEDGER="$DIR/.installed"
mark_installed() {  # mark_installed <имя>
  touch "$LEDGER" 2>/dev/null || return 0
  grep -qxF "$1" "$LEDGER" 2>/dev/null || printf '%s\n' "$1" >> "$LEDGER"
}
was_installed() { [ -f "$LEDGER" ] && grep -qxF "$1" "$LEDGER" 2>/dev/null; }

# ВАЖНО про MSYS/Cygwin: при поиске имени БЕЗ расширения оболочка подставляет
# .exe. То есть [ -f "$BIN/nuclei" ] отвечает «да», если на диске есть nuclei.exe,
# а rm -f "$BIN/nuclei" вслед за этим nuclei.exe и удаляет. Именно так арсенал
# терял 12 движков: проверка «осталась ли старая копия без .exe» срабатывала на
# только что установленный файл и тут же его сносила. Поэтому в Windows имена
# проверяем только с .exe, а удаляем через саму Windows.
have() {  # have <имя> — установлен ли инструмент арсенала
  local n="$1"
  if [ -n "$EXE" ]; then
    [ -f "$BIN/$n$EXE" ] && return 0
    [ -f "$BIN/$n.cmd" ] && return 0      # обёртка-запускатель (так подключаем nmap из Program Files)
    return 1
  fi
  [ -x "$BIN/$n" ] && return 0
  return 1
}

rm_stale() {  # rm_stale <имя> — удалить старую копию без .exe, если она РЕАЛЬНО есть
  local f="$BIN/$1"
  # Вне Windows «двойников» не бывает: $BIN/<имя> там и есть сам бинарник,
  # так что чистить нечего (иначе удалим только что установленный файл).
  [ -n "$EXE" ] || return 0
  [ "${#PY[@]}" -gt 0 ] || return 0
  # спрашиваем у Windows: она, в отличие от MSYS, .exe не подставляет
  "${PY[@]}" - "$f" <<'PY'
import os, sys
p = sys.argv[1]
if not os.path.isfile(p) or p.lower().endswith(".exe"):
    sys.exit(0)
try:
    os.remove(p)
except OSError:
    pass
PY
}
binfile() {  # binfile <имя> — фактический путь к файлу инструмента
  if [ -n "$EXE" ] && [ -f "$BIN/$1$EXE" ]; then printf '%s' "$BIN/$1$EXE"; else printf '%s' "$BIN/$1"; fi
}
launcher() {  # launcher <имя> — чем реально запускать инструмент (в env.sh/env.ps1)
  local n="$1"
  if [ -n "$EXE" ]; then
    [ -f "$BIN/$n$EXE" ] && { printf '%s' "$BIN/$n$EXE"; return 0; }
    [ -f "$BIN/$n.cmd" ] && { printf '%s' "$BIN/$n.cmd"; return 0; }
  fi
  printf '%s' "$BIN/$n"
}

say "Среда: $OSNAME, arch=$ARCH, python=$PYNAME"
say "Арсенал: $DIR"

# ---------------------------------------------------------------------------
#  GitHub: список ассетов последнего релиза (с обходом лимита API)
# ---------------------------------------------------------------------------
gh_assets() {  # gh_assets <owner/repo> — все URL ассетов, по одному в строке
  local repo="$1" tag f
  f="$TMPD/gh_$(printf '%s' "$1" | tr '/' '_').lst"
  if [ -s "$f" ] && [ "$FORCE" = "0" ]; then cat "$f"; return 0; fi
  : > "$f"
  # 1) официальный API (60 запросов/час на IP без токена — быстро кончается)
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -m 60 -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
      | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 >> "$f"
  fi
  if [ ! -s "$f" ]; then
    curl -fsSL -m 60 -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
      | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 >> "$f"
  fi
  # 2) запасной путь: страница ассетов релиза — не расходует лимит API
  if [ ! -s "$f" ]; then
    tag="$(curl -sSL -m 60 -o /dev/null -w '%{url_effective}' \
             "https://github.com/$repo/releases/latest" 2>/dev/null | sed -e 's|.*/tag/||')"
    if [ -n "$tag" ] && [ "$tag" != "https://github.com/$repo/releases/latest" ]; then
      curl -fsSL -m 60 "https://github.com/$repo/releases/expanded_assets/$tag" 2>/dev/null \
        | grep -oE 'href="/[^"]+/releases/download/[^"]+"' \
        | sed -e 's|^href="|https://github.com|' -e 's|"$||' >> "$f"
    fi
  fi
  [ -s "$f" ] || return 1
  sort -u "$f"
}

# Причина отказа хранится в файле: gh_asset вызывается через $(...), то есть
# в подоболочке, и обычная переменная оттуда не возвращается.
GH_ERRF="$TMPD/.gh_err"
gh_err() { [ -s "$GH_ERRF" ] && cat "$GH_ERRF" || printf 'ссылка не найдена'; }

gh_asset() {  # gh_asset <owner/repo> <regexp> — первый подходящий URL
  local list url
  : > "$GH_ERRF"
  list="$(gh_assets "$1")"
  if [ -z "$list" ]; then
    printf 'не удалось получить список релизов %s (сеть, прокси или лимит API GitHub; помогает export GITHUB_TOKEN=...)
' "$1" > "$GH_ERRF"
    return 1
  fi
  url="$(printf '%s\n' "$list" | grep -E "$2" | head -1)"
  if [ -z "$url" ]; then
    printf 'в последнем релизе нет сборки под шаблон /%s/ (ОС=%s, arch=%s)
' "$2" "$GOOS" "$ARCH" > "$GH_ERRF"
    return 1
  fi
  printf '%s' "$url"
}

EXTRACTOR=""
extract_member() {  # extract_member <архив> <куда> <имя-члена>...
  local arc="$1" out="$2"; shift 2
  local m ln b f list
  EXTRACTOR=""
  if command -v unzip >/dev/null 2>&1; then
    for m in "$@"; do
      if unzip -l "$arc" "$m" >/dev/null 2>&1; then
        unzip -p "$arc" "$m" > "$out" 2>/dev/null
        [ -s "$out" ] && { EXTRACTOR="unzip"; return 0; }
      fi
    done
  fi
  if command -v tar >/dev/null 2>&1; then
    list="$(tar -tf "$arc" 2>/dev/null)" || list=""
    if [ -n "$list" ]; then
      for m in "$@"; do
        f=""
        while IFS= read -r ln; do
          b="${ln##*/}"
          [ "$b" = "$m" ] && { f="$ln"; break; }
        done <<< "$list"
        [ -n "$f" ] || continue
        tar -xOf "$arc" "$f" > "$out" 2>/dev/null
        [ -s "$out" ] && { EXTRACTOR="tar"; return 0; }
      done
    fi
  fi
  if [ "${#PY[@]}" -gt 0 ]; then
    # пути передаём АРГУМЕНТАМИ (оболочка MSYS сама переведёт их в C:\...),
    # внутри кода python никаких путей не пишем
    "${PY[@]}" - "$arc" "$out" "$@" <<'PY'
import os, sys, tarfile, zipfile
src, out = sys.argv[1], sys.argv[2]
wanted = [w for w in sys.argv[3:] if w]
def base(n): return os.path.basename(n.replace("\\", "/"))
try:
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            names = z.namelist()
            for w in wanted:
                if w in names:
                    target = w; break
                c = [n for n in names if base(n) == w]
                if c:
                    target = c[0]; break
            else:
                raise SystemExit("член архива не найден: " + ", ".join(wanted))
            with z.open(target) as f, open(out, "wb") as o:
                o.write(f.read())
    else:
        with tarfile.open(src) as t:
            ms = [m for m in t.getmembers() if m.isfile()]
            for w in wanted:
                c = [m for m in ms if base(m.name) == w]
                if c:
                    member = c[0]; break
            else:
                raise SystemExit("член архива не найден: " + ", ".join(wanted))
            with t.extractfile(member) as f, open(out, "wb") as o:
                o.write(f.read())
except SystemExit as e:
    sys.stderr.write(str(e) + "\n"); sys.exit(2)
PY
    [ -s "$out" ] && { EXTRACTOR="python"; return 0; }
  fi
  return 1
}

install_from_url() {  # install_from_url <имя> <url> <член-архива...>
  local name="$1" url="$2"; shift 2
  local out arc="$TMPD/$name.dl"
  out="$BIN/$name$EXE"
  if [ -z "$url" ]; then fail "$name: $(gh_err)"; return 1; fi
  if [ "$SELFTEST" = "1" ]; then ok "$name: $url"; return 0; fi
  curl -fsSL -m 600 --retry 2 "$url" -o "$arc" || { fail "$name: скачивание не удалось ($url)"; return 1; }
  # защита от «скачалась HTML-страница ошибки»
  case "$(head -c 2 "$arc" 2>/dev/null | tr -d '\0')" in
    PK|"$(printf '\037\213')") : ;;
    *) fail "$name: скачался не архив (проверь сеть/прокси)"; rm -f "$arc"; return 1 ;;
  esac
  if extract_member "$arc" "$out" "$@"; then
    chmod +x "$out" 2>/dev/null || true
    # старая копия без .exe (например, Linux-бинарник от прошлой установки)
    rm_stale "$name"
    mark_installed "$name"
    ok "$name: $(basename "$url") [$EXTRACTOR]"
  else
    fail "$name: не удалось достать бинарник из $(basename "$url")"
    rm -f "$out"
  fi
  rm -f "$arc"
}

install_tool() {  # install_tool <имя> <owner/repo> <regexp> [raw]
  local name="$1" repo="$2" rx="$3" raw="${4:-}" url
  want "$name" || return 0
  if [ "$FORCE" = "0" ] && have "$name"; then ok "$name уже установлен"; return 0; fi
  if [ "$FAST" = "1" ]; then
    case "$name" in trivy|trufflehog|osv-scanner|gitleaks|testssl.sh|nikto|nmap) miss "$name: пропущен в быстром режиме"; return 0 ;; esac
  fi
  url="$(gh_asset "$repo" "$rx")" || url=""
  if [ "$raw" = "raw" ]; then
    if [ -z "$url" ]; then fail "$name: $(gh_err)"; return 1; fi
    if [ "$SELFTEST" = "1" ]; then ok "$name: $url"; return 0; fi
    if curl -fsSL -m 300 --retry 2 "$url" -o "$BIN/$name$EXE" && chmod +x "$BIN/$name$EXE"; then
      mark_installed "$name"; ok "$name: $(basename "$url")"
    else
      fail "$name: не скачался"
    fi
    return 0
  fi
  install_from_url "$name" "$url" "$name$EXE" "$name"
}

# ---------------------------------------------------------------------------
#  1. libpcap / npcap (нужны naabu для SYN-сканирования)
# ---------------------------------------------------------------------------
if want naabu; then
  say "== 1/5  Библиотека захвата пакетов (для naabu)"
  if [ "$IS_WIN" = "1" ]; then
    npcap_here() { [ -f "/c/Windows/System32/Npcap/wpcap.dll" ] || [ -f "/c/Windows/System32/wpcap.dll" ]; }
    if npcap_here; then
      ok "Npcap: на месте (доступен SYN-режим: naabu -scan-type s)"
    else
      NPCAP_EXE=""
      if [ "${ASM_NPCAP:-}" = "auto" ]; then
        say "  · Npcap: ищу свежий установщик на npcap.com ..."
        NPCAP_VER="$(curl -fsSL -m 60 https://npcap.com/dist/ 2>/dev/null \
          | grep -oE 'npcap-[0-9]+\.[0-9]+\.exe' | sed 's/npcap-//; s/\.exe//' | sort -V | tail -1)"
        if [ -n "$NPCAP_VER" ] && curl -fL -m 600 "https://npcap.com/dist/npcap-$NPCAP_VER.exe" \
             -o "$TMPD/npcap-$NPCAP_VER.exe" 2>/dev/null; then
          NPCAP_EXE="$TMPD/npcap-$NPCAP_VER.exe"; chmod +x "$NPCAP_EXE" 2>/dev/null || true
          ok "Npcap: скачан npcap-$NPCAP_VER.exe"
        else
          miss "Npcap: установщик не скачался (нет сети или npcap.com недоступен)"
        fi
      elif [ -n "${ASM_NPCAP:-}" ] && [ -f "$ASM_NPCAP" ]; then
        NPCAP_EXE="$ASM_NPCAP"
      fi
      if [ -n "$NPCAP_EXE" ]; then
        # Тихой установки у бесплатного Npcap нет (/S — только OEM), поэтому
        # установщик откроет окно: нужно подтвердить UAC и пройти мастер.
        say "  · Npcap: запускаю $(win_path "$NPCAP_EXE") — подтверди UAC и пройди мастер"
        say "    В мастере оставь галку 'Install Npcap in WinPcap API-compatible Mode'."
        "$NPCAP_EXE" || true
        say "  · Npcap: мастер закрыт, проверяю ..."
        if npcap_here; then ok "Npcap: установлен (SYN-режим naabu доступен)"
        else miss "Npcap: установщик отработал, но wpcap.dll не появился (нужны права администратора)"; fi
      else
        miss "Npcap: не найден — naabu работает в connect-режиме (это его режим по умолчанию, Npcap не нужен)"
        miss "  Без Npcap недоступен только SYN-режим (naabu -scan-type s). Поставить:"
        miss "    a) bash bin/install-tools.sh --only=naabu --npcap"
        miss "       — скрипт сам скачает свежий установщик и откроет мастер (нужны права администратора)"
        miss "    b) bash bin/install-tools.sh --only=naabu --npcap=/c/Users/<ты>/Downloads/npcap-1.89.exe"
        miss "    c) вручную: https://npcap.com/dist/npcap-1.89.exe"
      fi
    fi
  elif [ "$SELFTEST" = "1" ]; then
    miss "libpcap: .deb с deb.debian.org (только Linux/amd64) — в --selftest не качаем"
  elif [ ! -e "$LIB/libpcap.so.0.8" ]; then
    DEB_URL=""
    if [ "$GOOS" = "linux" ]; then
      for u in "http://deb.debian.org/debian/pool/main/libp/libpcap/libpcap0.8_1.10.3-1_amd64.deb" \
               "http://deb.debian.org/debian/pool/main/libp/libpcap/libpcap0.8_1.10.5-2_amd64.deb"; do
        if curl -fsSL -m 60 "$u" -o "$TMPD/libpcap.deb" 2>/dev/null; then DEB_URL="$u"; break; fi
      done
    fi
    if [ -n "$DEB_URL" ] && command -v dpkg-deb >/dev/null 2>&1; then
      dpkg-deb -x "$TMPD/libpcap.deb" "$TMPD/libpcap_x" >/dev/null 2>&1 || true
      so=$(find "$TMPD/libpcap_x" -name 'libpcap.so.*' 2>/dev/null | head -1)
      if [ -n "$so" ]; then cp -f "$so" "$LIB/libpcap.so.0.8"; ok "libpcap: $(basename "$so")"
      else fail "libpcap: не удалось распаковать (naabu будет работать в connect-режиме)"; fi
      rm -rf "$TMPD/libpcap.deb" "$TMPD/libpcap_x"
    else
      miss "libpcap: не скачан (naabu будет работать в connect-режиме; остальное не затрагивает)"
    fi
  else
    ok "libpcap уже есть"
  fi
fi

# ---------------------------------------------------------------------------
#  2. ProjectDiscovery — основные движки
# ---------------------------------------------------------------------------
say "== 2/5  Движки ProjectDiscovery (nuclei, naabu, subfinder, httpx, dnsx, tlsx, katana)"
while IFS=';' read -r name repo rx; do
  [ -n "$name" ] || continue
  install_tool "$name" "$repo" "$rx"
done <<EOF
nuclei;projectdiscovery/nuclei;_${GOOS}_${ARCH}\.zip\$
naabu;projectdiscovery/naabu;_${GOOS}_${ARCH}\.zip\$
subfinder;projectdiscovery/subfinder;_${GOOS}_${ARCH}\.zip\$
httpx;projectdiscovery/httpx;_${GOOS}_${ARCH}\.zip\$
dnsx;projectdiscovery/dnsx;_${GOOS}_${ARCH}\.zip\$
tlsx;projectdiscovery/tlsx;_${GOOS}_${ARCH}\.zip\$
katana;projectdiscovery/katana;_${GOOS}_${ARCH}\.zip\$
EOF

# ---------------------------------------------------------------------------
#  3. Остальные инструменты
# ---------------------------------------------------------------------------
say "== 3/5  Прочие инструменты (ffuf, gau, amass, trivy, gitleaks, trufflehog, osv-scanner, nikto, testssl.sh)"
while IFS=';' read -r name repo rx mode; do
  [ -n "$name" ] || continue
  install_tool "$name" "$repo" "$rx" "$mode"
done <<EOF
ffuf;ffuf/ffuf;ffuf_[0-9.]+_${GOOS}_${ARCH}\.(tar\.gz|zip)\$;
gau;lc/gau;gau_[0-9.]+_${GOOS}_${ARCH}\.(tar\.gz|zip)\$;
amass;owasp-amass/amass;amass_${GOOS}_${ARCH}\.(zip|tar\.gz)\$;
trivy;aquasecurity/trivy;${TRIVY_PAT};
trufflehog;trufflesecurity/trufflehog;trufflehog_[0-9.]+_${GOOS}_${ARCH}\.tar\.gz\$;
osv-scanner;google/osv-scanner;osv-scanner_${GOOS}_${ARCH}(\.exe)?\$;raw
gitleaks;gitleaks/gitleaks;gitleaks_[0-9.]+_${GOOS}_${GL_ARCH}\.(tar\.gz|zip)\$;
EOF

# ---- nmap: только Linux (сборка из исходников). Для Windows переносимого
# ---- архива на nmap.org больше нет (последний win32.zip — 7.92), а setup.exe
# ---- требует прав администратора; порты закрывает naabu.
if want nmap; then
  if [ "$FAST" = "1" ]; then miss "nmap: пропущен в быстром режиме"
  elif [ "$IS_WIN" = "1" ]; then
    # Переносимого архива для Windows на nmap.org больше нет (последний win32.zip — 7.92),
    # поэтому берём nmap из официального setup.exe и подключаем его в арсенал обёрткой.
    nmap_win_find() {  # печатает путь к nmap.exe, если он уже стоит
      local c
      if [ -n "${ASM_NMAP_EXE:-}" ] && [ -f "$ASM_NMAP_EXE" ]; then printf '%s' "$ASM_NMAP_EXE"; return 0; fi
      for c in "/c/Program Files (x86)/Nmap/nmap.exe" "/c/Program Files/Nmap/nmap.exe" \
               "$(command -v nmap 2>/dev/null)"; do
        [ -n "$c" ] || continue
        case "$c" in "$BIN"/*) continue ;; esac          # не ссылаться на собственную обёртку
        [ -f "$c" ] && { printf '%s' "$c"; return 0; }
      done
      return 1
    }
    nmap_win_link() {  # nmap_win_link <путь к nmap.exe> — обёртки в bin/ + учёт
      printf '#!/bin/sh\nexec "%s" "$@"\n' "$1" > "$BIN/nmap"
      chmod +x "$BIN/nmap"
      printf '@echo off\r\n"%s" %%*\r\n' "$(win_path "$1")" > "$BIN/nmap.cmd"
      mark_installed nmap
      ok "nmap: подключён из $(win_path "$(dirname "$1")") — $("$BIN/nmap" --version 2>/dev/null | head -1)"
    }
    NMAP_SRC="$(nmap_win_find)"
    if [ -n "$NMAP_SRC" ]; then
      nmap_win_link "$NMAP_SRC"
    else
      NMAP_SETUP=""
      if [ "${ASM_NMAP:-}" = "auto" ]; then
        NMAP_VER_W="$(curl -fsSL -m 60 https://nmap.org/dist/ 2>/dev/null \
          | grep -oE 'nmap-[0-9.]+-setup\.exe' | sed 's/nmap-//; s/-setup\.exe//' | sort -V | tail -1)"
        [ -n "$NMAP_VER_W" ] || NMAP_VER_W="7.991"
        say "  · nmap: качаю установщик nmap-$NMAP_VER_W-setup.exe (~37 МБ) ..."
        curl -fL -m 1800 "https://nmap.org/dist/nmap-$NMAP_VER_W-setup.exe" \
          -o "$TMPD/nmap-$NMAP_VER_W-setup.exe" 2>/dev/null && NMAP_SETUP="$TMPD/nmap-$NMAP_VER_W-setup.exe"
        [ -n "$NMAP_SETUP" ] && chmod +x "$NMAP_SETUP" 2>/dev/null || true
        [ -n "$NMAP_SETUP" ] || miss "nmap: установщик не скачался"
      elif [ -n "${ASM_NMAP:-}" ] && [ -f "$ASM_NMAP" ]; then
        NMAP_SETUP="$ASM_NMAP"
      fi
      if [ -n "$NMAP_SETUP" ]; then
        say "  · nmap: запускаю $(win_path "$NMAP_SETUP") — подтверди UAC и пройди мастер"
        say "    Мастер предложит поставить и Npcap: согласись — закроются оба пункта."
        "$NMAP_SETUP" || true
        say "  · nmap: мастер закрыт, ищу установленный nmap.exe ..."
        NMAP_SRC="$(nmap_win_find)"
        if [ -n "$NMAP_SRC" ]; then nmap_win_link "$NMAP_SRC"
        else miss "nmap: nmap.exe не найден после установки (проверь каталог установки)"; fi
      else
        miss "nmap: не установлен (порты закрывает naabu). Поставить, если нужен:"
        miss "  a) bash bin/install-tools.sh --only=nmap --nmap"
        miss "     — скачает официальный setup.exe с nmap.org и откроет мастер (он же ставит Npcap)"
        miss "  b) bash bin/install-tools.sh --only=nmap --nmap=/c/Users/<ты>/Downloads/nmap-7.991-setup.exe"
        miss "  c) вручную: https://nmap.org/dist/nmap-7.991-setup.exe  (путь по умолчанию подойдёт)"
        miss "  После установки запусти скрипт ещё раз — он сам подключит nmap в арсенал."
      fi
    fi
  elif [ "$SELFTEST" = "1" ]; then miss "nmap: сборка из исходников ${ASM_NMAP_VER:-v7.991} (нужен gcc) — в --selftest не собираем"
  elif [ "$FORCE" = "1" ] || ! have nmap; then
    say "  · nmap: сборка из исходников (нужен gcc; ~1–2 минуты)"
    NMAP_VER="${ASM_NMAP_VER:-v7.991}"
    if [ "$GOOS" = "linux" ] && command -v gcc >/dev/null 2>&1; then
      if curl -fsSL -m 600 "https://api.github.com/repos/nmap/nmap/tarball/refs/tags/${NMAP_VER}" -o "$TMPD/nmap-src.tar.gz"; then
        rm -rf "$TMPD/nmap-src" && mkdir -p "$TMPD/nmap-src"
        tar xzf "$TMPD/nmap-src.tar.gz" -C "$TMPD/nmap-src" --strip-components=1
        ( cd "$TMPD/nmap-src" && ./configure --without-zenmap --without-ncat --without-ndiff --without-nping \
            --prefix="$DIR" > "$TMPD/nmap-conf.log" 2>&1 && make -j"$(nproc)" > "$TMPD/nmap-make.log" 2>&1 \
            && make install > "$TMPD/nmap-install.log" 2>&1 )
        if have nmap; then ok "nmap: $($(binfile nmap) --version 2>/dev/null | head -1)"
        else fail "nmap: сборка не удалась (см. $TMPD/nmap-*.log)"; fi
      else
        fail "nmap: исходники не скачались"
      fi
    else
      miss "nmap: нужен gcc (пропускаем; порты закрывает naabu)"
    fi
  else ok "nmap уже установлен"; fi
fi

# ---- perl-модуль XML::Writer: нужен nikto для отчёта в JSON -----------------
if want nikto; then
if command -v perl >/dev/null 2>&1; then
  if ! PERL5LIB="$DIR/perl-libs" perl -MXML::Writer -e 1 2>/dev/null; then
    mkdir -p "$DIR/perl-libs/XML"
    url=$(curl -fsSL -m 30 https://fastapi.metacpan.org/v1/release/XML-Writer 2>/dev/null \
          | grep -oE '"download_url":"[^"]+"' | cut -d'"' -f4)
    [ -n "$url" ] || url="https://cpan.metacpan.org/authors/id/J/JO/JOSEPHW/XML-Writer-0.900.tar.gz"
    if curl -fsSL -m 60 "$url" -o "$TMPD/xmlw.tgz" 2>/dev/null; then
      rm -rf "$TMPD/xmlw" && mkdir -p "$TMPD/xmlw"
      tar xzf "$TMPD/xmlw.tgz" -C "$TMPD/xmlw" --strip-components=1 2>/dev/null
      src=$(find "$TMPD/xmlw" -name 'Writer.pm' 2>/dev/null | head -1)
      if [ -n "$src" ]; then cp "$src" "$DIR/perl-libs/XML/Writer.pm"; fi
      rm -rf "$TMPD/xmlw" "$TMPD/xmlw.tgz"
    fi
  fi
  if PERL5LIB="$DIR/perl-libs" perl -MXML::Writer -e 1 2>/dev/null; then
    ok "perl XML::Writer: на месте (нужен nikto для отчёта в JSON)"
  else
    miss "perl XML::Writer: не установился (вручную: cpan -T XML::Writer)"
  fi
  if ! PERL5LIB="$DIR/perl-libs" perl -MNet::SSLeay -e 1 2>/dev/null; then
    miss "perl Net::SSLeay: нет — nikto не сможет проверять HTTPS-цели (нужен собранный модуль; cpan -T Net::SSLeay)"
  fi
else
  miss "perl: не найден (nikto без него не работает)"
fi

# ---- nikto -------------------------------------------------------------------
nikto_ok() { [ -x "$DIR/nikto/program/nikto.pl" ] && [ -d "$DIR/nikto/program/plugins" ] && [ -d "$DIR/nikto/program/databases" ]; }
if [ "$FAST" = "1" ]; then miss "nikto: пропущен в быстром режиме"
elif [ "$FORCE" = "1" ] || ! nikto_ok; then
  if [ "$SELFTEST" = "1" ]; then miss "nikto: копия репозитория sullo/nikto (--selftest ничего не качает)"
  elif command -v perl >/dev/null 2>&1; then
    rm -rf "$DIR/nikto.part" "$TMPD/nikto-src" "$TMPD/nikto.tgz"
    if git clone --depth 1 -q https://github.com/sullo/nikto.git "$DIR/nikto.part" 2>/dev/null \
       && [ -d "$DIR/nikto.part/program/plugins" ] && [ -d "$DIR/nikto.part/program/databases" ]; then
      rm -rf "$DIR/nikto" && mv "$DIR/nikto.part" "$DIR/nikto"
    else
      miss "nikto: копия репозитория неполная — беру архив"
      rm -rf "$DIR/nikto.part"
      mkdir -p "$TMPD/nikto-src"
      if curl -fsSL -m 120 https://codeload.github.com/sullo/nikto/tar.gz/refs/heads/master -o "$TMPD/nikto.tgz" 2>/dev/null \
         && tar xzf "$TMPD/nikto.tgz" -C "$TMPD/nikto-src" --strip-components=1 2>/dev/null \
         && [ -d "$TMPD/nikto-src/program/databases" ]; then
        rm -rf "$DIR/nikto" && mkdir -p "$DIR/nikto" && cp -r "$TMPD/nikto-src"/. "$DIR/nikto/"
      fi
      rm -rf "$TMPD/nikto-src" "$TMPD/nikto.tgz"
    fi
    if nikto_ok; then
      ok "nikto: $(PERL5LIB="$DIR/perl-libs" perl "$DIR/nikto/program/nikto.pl" -Version 2>/dev/null | head -1)"
    else
      fail "nikto: не установился (нужны perl и сеть)"
    fi
  else
    miss "nikto: нужен perl"
  fi
else ok "nikto уже установлен"; fi
fi

# ---- testssl.sh --------------------------------------------------------------
# testssl.sh ищет каталог etc/ РЯДОМ с собой, поэтому в bin/ кладём обёртку,
# а не копию скрипта: копия падает с "No cipher mapping file found!".
if want testssl.sh; then
testssl_tree_ok() { [ -x "$DIR/testssl/testssl.sh" ] && [ -d "$DIR/testssl/etc" ]; }
# Обёртка должна отвечать на --version сама: testssl.sh без цели может не напечатать
# версию в pipe, и в сводке вместо "3.2.0" появлялось "установлен".
testssl_link_ok() { grep -q 'ASM-TESTSSL-VER' "$BIN/testssl.sh" 2>/dev/null; }
write_testssl_wrapper() {
  {
    printf '#!/bin/sh\n# ASM-TESTSSL-WRAPPER\n# ASM-TESTSSL-VER %s\n' "$(testssl_ver)"
    printf 'if [ "$1" = "--version" ] || [ "$1" = "-V" ]; then echo "testssl.sh %s"; exit 0; fi\n' \
      "$(testssl_ver)"
    printf 'exec "%s/testssl/testssl.sh" "$@"\n' "$DIR"
  } > "$BIN/testssl.sh"
  chmod +x "$BIN/testssl.sh"
}
testssl_ver() { grep -m1 -oE 'VERSION="[0-9.]+"' "$DIR/testssl/testssl.sh" 2>/dev/null | grep -oE '[0-9.]+'; }
if [ "$FAST" = "1" ]; then miss "testssl.sh: пропущен в быстром режиме"
elif testssl_tree_ok && ! testssl_link_ok; then
  # дерево на месте, но в bin/ лежит старая плоская копия — лечим без перекачки
  write_testssl_wrapper
  ok "testssl.sh $(testssl_ver): обёртка в bin/ исправлена (etc/ теперь находится)"
elif [ "$FORCE" = "1" ] || ! testssl_tree_ok; then
  if [ "$SELFTEST" = "1" ]; then miss "testssl.sh: архив v3.2.0 с GitHub (--selftest ничего не качает)"
  elif curl -fsSL -m 300 "https://codeload.github.com/drwetter/testssl.sh/tar.gz/refs/tags/v3.2.0" \
       -o "$TMPD/testssl.tgz" 2>/dev/null; then
    rm -rf "$TMPD/testssl-src" && mkdir -p "$TMPD/testssl-src"
    tar xzf "$TMPD/testssl.tgz" -C "$TMPD/testssl-src" --strip-components=1
    rm -rf "$DIR/testssl" && mkdir -p "$DIR/testssl"
    cp -r "$TMPD/testssl-src/testssl.sh" "$TMPD/testssl-src/etc" "$TMPD/testssl-src/bin" "$DIR/testssl/" 2>/dev/null
    chmod +x "$DIR/testssl/testssl.sh"
    write_testssl_wrapper
    ok "testssl.sh: $(testssl_ver)"
    rm -rf "$TMPD/testssl-src" "$TMPD/testssl.tgz"
  else
    miss "testssl.sh: не скачался (необязателен)"
  fi
else ok "testssl.sh уже установлен ($(testssl_ver))"; fi
fi

# hexdump — им пользуется testssl.sh
if want testssl.sh; then
if [ "$FAST" = "1" ]; then miss "hexdump: пропущен в быстром режиме"; elif [ "$FORCE" = "1" ] || ! command -v hexdump >/dev/null 2>&1; then
  if [ ! -x "$BIN/hexdump" ] && [ -f "$ROOT/bin/hexdump" ]; then
    cp "$ROOT/bin/hexdump" "$BIN/hexdump" 2>/dev/null && chmod +x "$BIN/hexdump" 2>/dev/null
  fi
  [ -x "$BIN/hexdump" ] && ok "hexdump: совместимая замена для testssl.sh" || true
else ok "hexdump уже есть"; fi
fi

# резолвер: testssl.sh умеет работать с dig, host, drill ИЛИ nslookup
if want testssl.sh; then
if [ "$IS_WIN" = "1" ]; then
  if command -v nslookup >/dev/null 2>&1; then
    ok "резолвер: системный nslookup — testssl.sh умеет работать с ним (dig не обязателен)"
  else
    miss "резолвер: нет ни dig, ни nslookup — testssl.sh не запустится"
  fi
elif command -v dig >/dev/null 2>&1 || command -v host >/dev/null 2>&1 \
     || command -v drill >/dev/null 2>&1 || command -v nslookup >/dev/null 2>&1; then
  ok "резолвер: $(command -v dig || command -v host || command -v drill || command -v nslookup)"
elif [ "$SELFTEST" = "1" ]; then miss "резолвер: нет dig/host/drill/nslookup — пришлось бы качать .deb (в --selftest не качаем)"
elif command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1; then
  ( cd "$TMPD" || exit 1; rm -rf asm-dig; mkdir asm-dig; cd asm-dig || exit 1
    for p in bind9-dnsutils bind9-libs libuv1t64 libjemalloc2 liburcu8t64 libjson-c5 \
             libprotobuf-c1 libfstrm0 liblmdb0 libnghttp2-14 libmaxminddb0 libgssapi-krb5-2; do
      apt-get download "$p" >/dev/null 2>&1 || true
    done
    for f in *.deb; do [ -f "$f" ] && dpkg-deb -x "$f" root; done
    # библиотеки резолвера держим отдельно (lib-dns): через общий LD_LIBRARY_PATH
    # они подменяют системные и ломают другие инструменты (semgrep)
    mkdir -p "$DIR/lib-dns"
    for b in dig host nslookup; do
      [ -f "root/usr/bin/$b" ] || continue
      cp "root/usr/bin/$b" "$BIN/$b.real" && chmod +x "$BIN/$b.real"
      printf '#!/bin/sh\nLD_LIBRARY_PATH="%s" exec "%s" "$@"\n' "$DIR/lib-dns" "$BIN/$b.real" > "$BIN/$b"
      chmod +x "$BIN/$b"
    done
    find root/usr/lib -name '*.so*' -exec cp -Pn {} "$DIR/lib-dns/" \; 2>/dev/null
  ) >/dev/null 2>&1
  "$BIN/dig" +short example.com >/dev/null 2>&1 \
    && ok "dig: локальная копия (нужна testssl.sh)" || miss "dig: не собрался (testssl может не запуститься)"
else
  miss "резолвер: нет dig/host/drill/nslookup и нет apt-get — testssl.sh не запустится"
fi
fi

# ---------------------------------------------------------------------------
#  3б. Инструменты на Python: анализ кода и веб-приложений, поиск по смыслу
# ---------------------------------------------------------------------------
if [ "$SELFTEST" = "1" ]; then
  say "== 3б/5  Python-инструменты (пропущены в --selftest)"
elif [ -z "$ONLY" ] || want semgrep || want wapiti || want sqlite-vec; then
say "== 3б/5  Python-инструменты (semgrep, wapiti, sqlite-vec)"
if [ "$FAST" = "1" ]; then miss "python-инструменты: пропущены в быстром режиме"
elif [ "${#PY[@]}" = "0" ]; then miss "python: не найден (semgrep/wapiti не поставить)"
else
PYLIB="$DIR/pylibs"
mkdir -p "$PYLIB"
py_ok() { PYTHONPATH="$PYLIB" "${PY[@]}" -c "import $1" >/dev/null 2>&1; }
PIPLOG="$TMPD"
# в Windows pip кладёт запускалки в Scripts/, в Linux/macOS — в bin/
py_script() {  # py_script <имя>... — первая найденная запускалка внутри pylibs
  local n p
  for n in "$@"; do
    for p in "$PYLIB/Scripts/$n.exe" "$PYLIB/Scripts/$n" "$PYLIB/bin/$n" "$PYLIB/bin/$n.exe"; do
      [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
  done
  return 1
}
# разделитель PYTHONPATH и запись обёрток отличаются: в Windows это ';' и .cmd
if [ "$IS_WIN" = "1" ]; then
  SEP=";"; PYLIB_W="$(win_path "$PYLIB")"; BIN_W="$(win_path "$BIN")"
  PYLIB_SH="$PYLIB_W"      # в sh-обёртку тоже кладём C:\... — на автоперевод MSYS не полагаемся
else
  SEP=":"; PYLIB_W=""; BIN_W=""; PYLIB_SH="$PYLIB"
fi

if want semgrep; then
  if [ "$FORCE" = "1" ] || ! py_ok semgrep; then
    "${PY[@]}" -m pip install --quiet --disable-pip-version-check --target "$PYLIB" semgrep > "$PIPLOG/pip-semgrep.log" 2>&1 \
      && ok "semgrep: поставлен в проект" || miss "semgrep: pip не смог (см. $PIPLOG/pip-semgrep.log)"
  else ok "semgrep уже установлен"; fi
fi

if want wapiti; then
  if [ "$FORCE" = "1" ] || ! py_ok wapitiCore; then
    "${PY[@]}" -m pip install --quiet --disable-pip-version-check --target "$PYLIB" wapiti3 > "$PIPLOG/pip-wapiti.log" 2>&1 \
      && ok "wapiti: поставлен в проект" || miss "wapiti: pip не смог (см. $PIPLOG/pip-wapiti.log)"
  else ok "wapiti уже установлен"; fi
fi

if want semgrep-rules; then
  if [ "$FORCE" = "1" ] || [ ! -d "$DIR/semgrep-rules/python" ]; then
    rm -rf "$DIR/semgrep-rules"
    git clone --depth 1 -q https://github.com/semgrep/semgrep-rules.git "$DIR/semgrep-rules" 2>/dev/null \
      && ok "semgrep-rules: $(find "$DIR/semgrep-rules" -name '*.yaml' | wc -l | tr -d ' ') правил сообщества" \
      || miss "semgrep-rules не скачались (semgrep будет брать облачный профиль p/security-audit)"
  else ok "semgrep-rules уже установлены"; fi
fi

report_wrapper() {  # report_wrapper <имя> <обёртка> — проверить и честно показать ошибку
  local n="$1" w="$2" out
  out="$("$w" --version 2>&1 | tr -d '\r' | sed -e 's/\x1b\[[0-9;]*m//g' | grep -v '^[[:space:]]*$')"
  if printf '%s' "$out" | grep -qiE 'traceback|error|no such file|can.t open file|modulenotfound'; then
    miss "$n: обёртка не работает — $(printf '%s' "$out" | tail -1)"
    miss "  полный вывод: $w --version"
  elif [ -n "$out" ]; then
    v="$(printf '%s' "$out" | grep -iE 'version|[0-9]+\.[0-9]+' | head -1)"
    [ -n "$v" ] || v="$(printf '%s' "$out" | head -1)"
    ok "$n: обёртка в каталоге арсенала ($v)"
  else
    ok "$n: обёртка создана (проверь: $n --version)"
  fi
}

# обёртки в bin/: так движок находит python-инструменты так же, как остальные.
# В Windows рядом кладём .cmd: оболочка Windows не понимает shebang, а пути
# внутри .cmd должны быть в нотации C:\...
WAPITI_CODE='import sys; from wapitiCore.main.wapiti import wapiti_asyncio_wrapper as m; sys.exit(m())'
PYW=""; PY_ARGS=""
if [ "${#PY[@]}" -gt 0 ]; then
  PYBIN_PATH="$(command -v "${PY[0]}" || true)"
  [ -n "$PYBIN_PATH" ] && PYW="$(win_path "$PYBIN_PATH")"
  if [ "${#PY[@]}" -gt 1 ]; then PY_ARGS="${PY[*]:1}"; else PY_ARGS=""; fi
fi

if want wapiti && py_ok wapitiCore; then
  {
    printf '#!/bin/sh\n'
    printf 'export PYTHONUTF8=1 PYTHONIOENCODING=utf-8\n'
    printf 'export PYTHONPATH="%s${PYTHONPATH:+%s$PYTHONPATH}"\n' "$PYLIB_SH" "$SEP"
    printf 'exec %s -c "%s" "$@"\n' "${PY[*]}" "$WAPITI_CODE"
  } > "$BIN/wapiti"
  chmod +x "$BIN/wapiti"
  if [ "$IS_WIN" = "1" ]; then
    {
      printf '@echo off\r\n'
      printf 'set PYTHONUTF8=1\r\nset PYTHONIOENCODING=utf-8\r\n'
      printf 'set "PYTHONPATH=%s%%PYTHONPATH%%"\r\n' "$PYLIB_W"
      printf '"%s" %s -c "%s" %%*\r\n' "$PYW" "$PY_ARGS" "$WAPITI_CODE"
    } > "$BIN/wapiti.cmd"
  fi
  report_wrapper wapiti "$BIN/wapiti"
fi

if want semgrep && py_ok semgrep; then
  # Точка входа из entry_points пакета: pysemgrep = semgrep.console_scripts.pysemgrep:main.
  # Файл-запускалку (Scripts/pysemgrep.exe) искать ненадёжно: pip кладёт её то в
  # Scripts/, то в bin/, а "python -m semgrep" с версии 1.38 просто выходит с кодом 2.
  # Загрузчик — отдельным файлом: так его одинаково зовут и sh-обёртка, и .cmd,
  # и в него же прячем import pywin32_bootstrap (на Windows он регистрирует
  # каталог DLL pywin32; без этого semgrep падает на "No module named 'pywintypes'").
  SEM_LAUNCH="$DIR/semgrep-cli.py"
  cat > "$SEM_LAUNCH" <<'PY'
import sys
try:
    import pywin32_bootstrap  # каталог DLL pywin32 (только Windows)
except Exception:
    pass
from semgrep.console_scripts.pysemgrep import main
sys.exit(main())
PY
  # pywin32 при установке в --target не регистрирует свой .pth, поэтому его
  # каталоги (win32, Pythonwin) и DLL (pywin32_system32) добавляем сами —
  # иначе semgrep падает с "No module named 'pywintypes'".
  SEM_PP="$PYLIB_SH"; SEM_DLLPATH="$PYLIB/pywin32_system32"
  for d in win32 win32/lib Pythonwin pythonwin; do
    [ -d "$PYLIB/$d" ] && SEM_PP="$SEM_PP$SEP$(win_path "$PYLIB/$d")"
  done
  {
    printf '#!/bin/sh\n'
    printf 'export PYTHONUTF8=1 PYTHONIOENCODING=utf-8\n'
    printf 'export PYTHONPATH="%s${PYTHONPATH:+%s$PYTHONPATH}"\n' "$SEM_PP" "$SEP"
    printf 'export PATH="%s:%s/bin:%s/Scripts:$PATH"\n' "$SEM_DLLPATH" "$PYLIB" "$PYLIB"
    printf 'exec %s "%s" "$@"\n' "${PY[*]}" "$SEM_LAUNCH"
  } > "$BIN/semgrep"
  chmod +x "$BIN/semgrep"
  if [ "$IS_WIN" = "1" ]; then
    SEM_PP_W="$SEM_PP"; SEM_DLL_W="$(win_path "$PYLIB/pywin32_system32")"
    {
      printf '@echo off\r\n'
      printf 'set PYTHONUTF8=1\r\nset PYTHONIOENCODING=utf-8\r\n'
      printf 'set "PYTHONPATH=%s%%PYTHONPATH%%"\r\n' "$SEM_PP_W"
      printf 'set "PATH=%s;%s\\bin;%s\\Scripts;%%PATH%%"\r\n' "$SEM_DLL_W" "$PYLIB_W" "$PYLIB_W"
      printf '"%s" %s "%s" %%*\r\n' "$PYW" "$PY_ARGS" "$(win_path "$SEM_LAUNCH")"
    } > "$BIN/semgrep.cmd"
  fi
  report_wrapper semgrep "$BIN/semgrep"
fi


if want sqlite-vec; then
  if [ "$FORCE" = "1" ] || ! py_ok sqlite_vec; then
    "${PY[@]}" -m pip install --quiet --disable-pip-version-check --target "$PYLIB" sqlite-vec > "$PIPLOG/pip-vec.log" 2>&1 \
      && ok "sqlite-vec: поиск по смыслу на векторах" || miss "sqlite-vec: pip не смог (см. $PIPLOG/pip-vec.log)"
  else ok "sqlite-vec уже установлен"; fi
fi

# модель для смыслового поиска (~0,5 ГБ) — только по явному желанию: ASM_WITH_MODEL=1
if [ "${ASM_WITH_MODEL:-0}" = "1" ]; then
  if py_ok fastembed; then ok "модель смыслового поиска уже есть"
  else "${PY[@]}" -m pip install --quiet --disable-pip-version-check --target "$PYLIB" fastembed > "$PIPLOG/pip-embed.log" 2>&1 \
       && ok "fastembed: локальная модель (0,5 ГБ)" || miss "fastembed: pip не смог"; fi
fi

fi
fi

# ---------------------------------------------------------------------------
#  4. Nuclei-шаблоны (13 000+ проверок)
# ---------------------------------------------------------------------------
if want templates; then
say "== 4/5  Шаблоны проверок nuclei"
# порог высокий намеренно: частично распакованный набор должен перекачиваться
if [ "$SELFTEST" = "1" ]; then
  miss "шаблоны: архив релиза nuclei-templates (--selftest ничего не качает)"
elif [ -d "$TPL" ] && [ "$(find "$TPL" -name '*.yaml' 2>/dev/null | wc -l)" -gt 12000 ] && [ "$FORCE" = "0" ]; then
  ok "шаблонов уже установлено: $(find "$TPL" -name '*.yaml' | wc -l | tr -d ' ')"
else
  tag="$(curl -fsSL -m 60 https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest 2>/dev/null \
        | grep -oE '"tag_name": *"[^"]+"' | cut -d'"' -f4 | head -1)"
  [ -n "$tag" ] || tag="main"
  url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${tag}.zip"
  [ "$tag" = "main" ] && url="https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main"
  arc="$TMPD/tpl.zip"
  say "  · шаблоны: качаю $url"
  if curl -fsSL -m 900 --retry 2 "$url" -o "$arc"; then
    say "  · скачано $(( $(wc -c < "$arc") / 1048576 )) МБ — распаковка ~13 700 файлов, это 1–5 минут без вывода, не прерывай"
    rm -rf "$TMPD/tplx" && mkdir -p "$TMPD/tplx"
    extracted=0
    if command -v unzip >/dev/null 2>&1 && unzip -q "$arc" -d "$TMPD/tplx" >/dev/null 2>&1; then
      extracted=1
    elif command -v tar >/dev/null 2>&1 && tar -xf "$arc" -C "$TMPD/tplx" >/dev/null 2>&1; then
      extracted=1
    elif [ "${#PY[@]}" -gt 0 ] && "${PY[@]}" - "$arc" "$TMPD/tplx" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
PY
    then extracted=1; fi
    src=$(find "$TMPD/tplx" -maxdepth 1 -type d -name 'nuclei-templates-*' | head -1)
    if [ "$extracted" = "1" ] && [ -n "$src" ]; then
      rm -rf "$TPL" && mv "$src" "$TPL"
      ok "шаблоны $tag: $(find "$TPL" -name '*.yaml' | wc -l | tr -d ' ') файлов"
    else
      fail "шаблоны: архив не распознан (скачано $(wc -c < "$arc" | tr -d ' ') байт)"
    fi
    rm -rf "$TMPD/tplx" "$arc"
  else
    fail "шаблоны: не скачались ($url)"
  fi
fi
fi

# ---------------------------------------------------------------------------
#  5. Словари (SecLists)
# ---------------------------------------------------------------------------
if want wordlists; then
say "== 5/5  Словари"
if [ "$SKIP_WORDS" = "1" ]; then miss "словари пропущены (--tools)"
elif [ "$SELFTEST" = "1" ]; then miss "словари: raw-файлы SecLists (--selftest ничего не качает)"
else
  get_words() {  # get_words <url> <файл>
    if [ -s "$WL/$2" ]; then ok "$2: $(wc -l < "$WL/$2" | tr -d ' ') строк"; return; fi
    if curl -fsSL -m 240 "$1" -o "$WL/$2" 2>/dev/null; then
      ok "$2: $(wc -l < "$WL/$2" | tr -d ' ') строк"
    else fail "$2: не скачался"; fi
  }
  get_words "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" "subdomains-110k.txt"
  get_words "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"  "subdomains-20k.txt"
  get_words "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"                    "dirs-common.txt"
  get_words "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt"          "dirs-small.txt"
fi
fi

# ---------------------------------------------------------------------------
#  Итог
# ---------------------------------------------------------------------------
cat > "$DIR/env.sh" <<EOF
# Подключение арсенала ASM из bash:  source $DIR/env.sh
export ASM_TOOLS_DIR="$DIR"
export PDCP_DIR="$DIR/pdcp"
export PYTHONPATH="$DIR/pylibs${PYTHONPATH:+$SEP$PYTHONPATH}"
export PATH="$BIN:\$PATH"
export LD_LIBRARY_PATH="$LIB:\${LD_LIBRARY_PATH:-}"
export ASM_ENGINE_EXT="$EXE"
export ASM_NAABU_BIN="$BIN/naabu$EXE"
export ASM_NUCLEI_BIN="$BIN/nuclei$EXE"
export ASM_NUCLEI_TEMPLATES="$TPL"
export ASM_SUBFINDER_BIN="$BIN/subfinder$EXE"
export ASM_HTTPX_BIN="$BIN/httpx$EXE"
export ASM_DNSX_BIN="$BIN/dnsx$EXE"
export ASM_TLSX_BIN="$BIN/tlsx$EXE"
export ASM_KATANA_BIN="$BIN/katana$EXE"
export ASM_FFUF_BIN="$BIN/ffuf$EXE"
export ASM_GAU_BIN="$BIN/gau$EXE"
export ASM_AMASS_BIN="$BIN/amass$EXE"
export ASM_TESTSSL_BIN="$BIN/testssl.sh"
export ASM_WORDLISTS="$WL"
export ASM_NMAP_BIN="$(launcher nmap)"
export ASM_TRIVY_BIN="$BIN/trivy$EXE"
export ASM_GITLEAKS_BIN="$BIN/gitleaks$EXE"
export ASM_TRUFFLEHOG_BIN="$BIN/trufflehog$EXE"
export ASM_OSV_BIN="$BIN/osv-scanner$EXE"
export ASM_SEMGREP_BIN="$BIN/semgrep"
export ASM_WAPITI_BIN="$BIN/wapiti"
# nikto лежит внутри своего каталога (program/nikto.pl) — движок находит его сам
EOF

if [ "$IS_WIN" = "1" ]; then
  DIR_W="$(win_path "$DIR")"; BIN_W="$(win_path "$BIN")"; TPL_W="$(win_path "$TPL")"; WL_W="$(win_path "$WL")"
  {
    echo "# Подключение арсенала ASM из PowerShell:  . '$DIR_W\env.ps1'"
    echo "\$env:ASM_TOOLS_DIR = '$DIR_W'"
    echo "\$env:PDCP_DIR = '$DIR_W\pdcp'"
    echo "\$env:ASM_NUCLEI_TEMPLATES = '$TPL_W'"
    echo "\$env:ASM_WORDLISTS = '$WL_W'"
    echo "\$env:ASM_ENGINE_EXT = '$EXE'"
    for t in nuclei naabu subfinder httpx dnsx tlsx katana ffuf gau amass trivy gitleaks trufflehog; do
      echo "\$env:$(printf 'ASM_%s_BIN' "$(printf '%s' "$t" | tr 'a-z-' 'A-Z_')") = '$BIN_W\\$t$EXE'"
    done
    echo "\$env:ASM_OSV_BIN = '$BIN_W\\osv-scanner$EXE'"
    echo "\$env:ASM_TESTSSL_BIN = '$BIN_W\\testssl.sh'"
    # обёртки без .exe: launcher сам выберет .exe -> .cmd -> просто имя
    for pair in "ASM_NMAP_BIN nmap" "ASM_SEMGREP_BIN semgrep" "ASM_WAPITI_BIN wapiti"; do
      echo "\$env:${pair%% *} = '$(win_path "$(launcher "${pair##* }")")'"
    done
    echo "\$env:PATH = '$BIN_W;' + \$env:PATH"
  } > "$DIR/env.ps1"
fi

say ""
say "== Готово. Проверка =="
# У многих движков -version сначала печатает ASCII-баннер: первую непустую строку
# брать нельзя, поэтому ищем строку со словом version / номером версии.
ver_of() {  # ver_of <файл>
  local f="$1" flag out
  for flag in --version -version -V -Version version; do
    out="$("$f" $flag 2>&1 | tr -d '\r' | sed -e 's/\x1b\[[0-9;]*m//g' \
      | grep -viE 'unknown (shorthand )?flag|^error|unrecognized option|unknown option|flag provided but not defined|expected command|display .*version|usage:|\[--|[|_/\\]{3}|^[[:space:]]*-|^[[:space:]]*$' \
      | grep -iE 'version|[0-9]+\.[0-9]+' | head -1)"
    [ -n "$out" ] && { printf '%s' "$out"; return 0; }
  done
  printf 'установлен'
}
VANISHED=""
for t in nuclei naabu subfinder httpx dnsx tlsx katana ffuf gau amass nmap trivy gitleaks trufflehog osv-scanner semgrep wapiti testssl.sh; do
  want "$t" || continue
  f="$(binfile "$t")"
  if [ -f "$f" ]; then
    printf '  %-12s %s\n' "$t" "$(ver_of "$f" | cut -c1-64)"
  elif was_installed "$t"; then
    printf '  %-12s \033[31mИсчез после установки\033[0m\n' "$t"
    VANISHED="$VANISHED $t"
  else
    printf '  %-12s \033[31mнет\033[0m\n' "$t"
  fi
done

if [ -n "$VANISHED" ]; then
  say ""
  fail "Эти файлы скрипт записал и проверил, но к концу работы их уже не было на диске:$VANISHED"
  say "  Причина выясняется диагностикой:  bash bin/diag-tools.sh"
  say "  (раздел 9 показывает, появляется ли файл сразу после записи и когда пропадает)"
fi

say ""
if [ "$SELFTEST" = "1" ]; then
  say "Это был --selftest: ничего не скачано. Запуск установки: bash bin/install-tools.sh"
else
  if [ "$IS_WIN" = "1" ]; then
    say "Подключить в Git Bash:     source $DIR/env.sh"
    say "Подключить в PowerShell:   . '$(win_path "$DIR")\\env.ps1'"
  else
    say "Подключить в текущей оболочке:  source $DIR/env.sh"
  fi
  say "Панель ASM сама найдёт движки в $BIN (ничего экспортировать не нужно)."
  [ "$IS_WIN" = "1" ] && say "В Windows исполняемые файлы имеют суффикс .exe — панель должна искать имя с .exe."
fi
