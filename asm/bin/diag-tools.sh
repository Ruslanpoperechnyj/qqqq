#!/usr/bin/env bash
# ============================================================================
#  ASM: диагностика арсенала — что реально лежит на диске и кто удаляет файлы
# ============================================================================
#  Ничего не переустанавливает. Создаёт два временных probe-файла в bin/ и
#  удаляет их в конце. Запуск:  bash bin/diag-tools.sh
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ASM_TOOLS_DIR:-$ROOT/build/tools}"
BIN="$DIR/bin"; PYLIB="$DIR/pylibs"

PY=()
if command -v python3 >/dev/null 2>&1; then PY=(python3)
elif command -v python >/dev/null 2>&1; then PY=(python)
elif command -v py >/dev/null 2>&1; then PY=(py -3)
fi
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi }

hr()  { printf '\n=== %s ===\n' "$*"; }
say() { printf '%s\n' "$*"; }

hr "1. Окружение"
say "uname -s   : $(uname -s)"
say "uname -m   : $(uname -m)"
say "bash       : $BASH_VERSION"
say "Арсенал    : $DIR"
for c in curl unzip tar python3 python py perl git powershell.exe; do
  printf '%-14s: %s\n' "$c" "$(command -v "$c" 2>/dev/null || echo '—')"
done

hr "2. Что лежит в bin/ прямо сейчас"
if [ -d "$BIN" ]; then
  ls -la "$BIN" 2>/dev/null | sed -e 's/^/  /'
  say ""
  say "  всего файлов : $(find "$BIN" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
  say "  с .exe       : $(find "$BIN" -maxdepth 1 -type f -name '*.exe' 2>/dev/null | wc -l | tr -d ' ')"
else
  say "  каталога $BIN нет"
fi

hr "3. Решающий опыт: одинаковые байты под двумя именами"
# Скачиваем dnsx (он из списка пропадающих) и кладём ОДИН И ТОТ ЖЕ набор байт
# под двумя именами: нейтральным и nuclei.exe.
#   исчезнут оба      -> удаление по содержимому (сканер узнаёт сам бинарник)
#   исчезнет nuclei   -> удаление по имени файла
#   выживут оба      -> сейчас файлы не удаляются, проблема была в другом
PROBE_URL="https://github.com/projectdiscovery/dnsx/releases/download/v1.3.1/dnsx_1.3.1_windows_amd64.zip"
SAFE="$BIN/__diag_safe.exe"; NAME="$BIN/nuclei.exe"
ARC="$DIR/tmp/__diag.zip"; mkdir -p "$DIR/tmp"
rm -f "$SAFE" "$NAME" "$ARC"
if curl -fsSL -m 300 "$PROBE_URL" -o "$ARC" 2>/dev/null; then
  got=0
  if command -v unzip >/dev/null 2>&1 && unzip -p "$ARC" dnsx.exe > "$SAFE" 2>/dev/null && [ -s "$SAFE" ]; then got=1; fi
  if [ "$got" = "0" ] && command -v python3 >/dev/null 2>&1; then
    python3 - "$ARC" "$SAFE" <<'PY' && got=1
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    open(sys.argv[2], "wb").write(z.read("dnsx.exe"))
PY
  fi
  if [ "$got" = "1" ]; then
    cp -f "$SAFE" "$NAME"
    say "  записано два одинаковых файла по $(wc -c < "$SAFE" | tr -d ' ') байт:"
    say "    A) $(basename "$SAFE")   (нейтральное имя)"
    say "    B) $(basename "$NAME")  (имя из списка пропадающих)"
    say "  наблюдаю 60 секунд…"
    for i in 1 2 3 4 5 6; do
      sleep 10
      a="нет"; b="нет"
      [ -f "$SAFE" ] && a="$(wc -c < "$SAFE" | tr -d ' ') байт"
      [ -f "$NAME" ] && b="$(wc -c < "$NAME" | tr -d ' ') байт"
      printf '  +%2s с   __diag_safe.exe: %-14s   nuclei.exe: %s\n' "$((i * 10))" "$a" "$b"
    done
    if [ -f "$SAFE" ] && [ -f "$NAME" ]; then
      say "  ВЫВОД: оба файла на месте — прямо сейчас ничего не удаляется."
    elif [ ! -f "$SAFE" ] && [ ! -f "$NAME" ]; then
      say "  ВЫВОД: исчезли ОБА — удаление по содержимому (сканер узнаёт бинарник)."
    elif [ -f "$SAFE" ] && [ ! -f "$NAME" ]; then
      say "  ВЫВОД: исчез только nuclei.exe — удаление по имени файла."
    else
      say "  ВЫВОД: исчез нейтральный, а nuclei.exe остался — неожиданно, покажи этот вывод."
    fi
  else
    say "  не удалось достать dnsx.exe из архива"
  fi
else
  say "  архив с dnsx не скачался — опыт пропущен"
fi
rm -f "$SAFE" "$NAME" "$ARC"

hr "4. Антивирус (Windows)"
if command -v powershell.exe >/dev/null 2>&1; then
  say "--- зарегистрированные антивирусы ---"
  powershell.exe -NoProfile -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | Format-Table -AutoSize" 2>&1 | sed -e 's/\r$//' -e 's/^/  /'
  say "--- состояние Defender ---"
  powershell.exe -NoProfile -Command "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled,IsTamperProtected,AntispywareEnabled | Format-List" 2>&1 | sed -e 's/\r$//' -e 's/^/  /'
  say "--- исключения Defender ---"
  powershell.exe -NoProfile -Command "(Get-MpPreference).ExclusionPath" 2>&1 | sed -e 's/\r$//' -e 's/^/  /'
  say "--- защита от нежелательного ПО (PUAProtection) ---"
  powershell.exe -NoProfile -Command "(Get-MpPreference).PUAProtection" 2>&1 | sed -e 's/\r$//' -e 's/^/  /'
  say "--- срабатывания, где в пути есть Arena ---"
  powershell.exe -NoProfile -Command "Get-MpThreatDetection | Where-Object { \$_.Resources -match 'Arena' } | Select-Object -Last 15 | Format-List ThreatID,InitialDetectionTime,Resources" 2>&1 | sed -e 's/\r$//' -e 's/^/  /'
else
  say "  powershell.exe недоступен (не Windows?)"
fi

hr "5. Раскладка pylibs (для semgrep/wapiti)"
for d in "$PYLIB/Scripts" "$PYLIB/bin"; do
  say "--- $d ---"
  if [ -d "$d" ]; then ls -la "$d" 2>/dev/null | head -20 | sed -e 's/^/  /'; else say "  (нет такого каталога)"; fi
done
say "--- чем на самом деле является pylibs/bin/pysemgrep ---"
if [ -e "$PYLIB/bin/pysemgrep" ]; then
  ls -la "$PYLIB/bin/pysemgrep" | sed -e 's/^/  /'
  file "$PYLIB/bin/pysemgrep" 2>/dev/null | sed -e 's/^/  /'
  say "  первые 120 байт:"
  head -c 120 "$PYLIB/bin/pysemgrep" 2>/dev/null | tr -d '\0' | sed -e 's/^/    /'
  say ""
else
  say "  файла нет (bash его тоже не видит)"
fi

hr "6. Обёртки semgrep и wapiti — полный вывод"
for w in semgrep wapiti; do
  say "--- $BIN/$w --version ---"
  if [ -f "$BIN/$w" ]; then
    "$BIN/$w" --version 2>&1 | head -25 | sed -e 's/^/  /'
  else
    say "  обёртки нет"
  fi
done

hr "7. nikto (его Defender помечал)"
for f in "$DIR/nikto/program/nikto.pl" "$DIR/nikto/program/plugins" "$DIR/nikto/program/databases"; do
  if [ -e "$f" ]; then say "  есть: $f"; else say "  НЕТ : $f"; fi
done

hr "8. Что видит MSYS и что видит Windows (сравнение имён файлов)"
# Если списки различаются — значит, bash и Windows смотрят на каталог по-разному,
# и это объяснило бы и пропавшие .exe, и «pysemgrep, который не открывается».
for d in "$BIN" "$PYLIB/bin"; do
  say "--- $d ---"
  say "  MSYS ls     : $(ls -1 "$d" 2>/dev/null | tr '\n' ' ')"
  if [ "${#PY[@]}" -gt 0 ]; then
    "${PY[@]}" -c "import os,sys
try:
    print('  Windows видит:', ' '.join(sorted(os.listdir(sys.argv[1]))))
except Exception as e:
    print('  Windows ошибка:', e)" "$(winpath "$d")" 2>&1 | sed -e 's/^/  /'
  else
    say "  python не найден"
  fi
done

hr "9. Опыт 2: штатная установка одного nuclei и наблюдение"
NX="nuclei"; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) NX="nuclei.exe" ;; esac
say "  запускаю: bash bin/install-tools.sh --tools --only=nuclei"
bash "$ROOT/bin/install-tools.sh" --tools --only=nuclei 2>&1 | sed -e 's/^/  /'
say ""
for i in 0 10 30; do
  [ "$i" -gt 0 ] && sleep "$i"
  if [ -f "$BIN/$NX" ]; then
    say "  +$i с: $NX на месте, $(wc -c < "$BIN/$NX" | tr -d ' ') байт"
  else
    say "  +$i с: $NX НЕТ"
  fi
done
say "  содержимое bin/ в конце опыта:"
ls -la "$BIN" 2>/dev/null | sed -e 's/^/    /'

hr "Готово"
say "Пришли весь этот вывод целиком."
