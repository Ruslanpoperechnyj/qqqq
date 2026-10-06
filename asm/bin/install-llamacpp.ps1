# bin/install-llamacpp.ps1 — движок llama.cpp (llama-server) + Gemma 4 12B QAT
#
# Зачем отдельный путь, если уже есть install-llm.ps1 (Ollama):
#   Ollama — это обёртка над тем же llama.cpp, но она не отдаёт наружу то,
#   что на 12 ГБ VRAM решает:
#     * --cache-type-k/-v q8_0 — квантованный KV-кеш: память под контекст
#       почти вдвое меньше (для 12 ГБ это разница между 16K и 32K);
#     * -fa (flash attention) и полный набор флагов (батчи, слои, потоки);
#     * спекулятивное декодирование через MTP-драфтер (см. ниже);
#     * новые кванты и архитектуры появляются здесь первыми.
#   Замеры 2026 на NVIDIA дают разницу от ~10% до 2x в пользу llama.cpp
#   (на Apple — в пределах шума; на CUDA обёртка стоит дороже).
#
# Модель: Gemma 4 12B it QAT, GGUF от Unsloth, UD-Q4_K_XL — 6,72 ГБ.
#   Лицензия на карточке модели: Apache 2.0. Перед платным договором всё
#   равно стоит глянуть страницу лицензии Gemma 4.
# Драфтер: mtp-gemma-4-12B-it.gguf — 254 МБ, Multi-Token Prediction.
#   Драфтер делит KV-кеш с основной моделью и НЕ меняет вывод (каждый его
#   токен проверяет основная модель), только ускоряет генерацию.
#
# Что делает скрипт:
#   1. качает свежую сборку llama.cpp под Windows CUDA (+cudart) из GitHub;
#   2. качает модель и MTP-драфтер в build\llm\models;
#   3. пишет build\llm\serve.cmd с настройками под 12 ГБ;
#   4. печатает, что вписать в проект.
#
# Использование:
#   powershell -ExecutionPolicy Bypass -File bin\install-llamacpp.ps1
#   powershell -ExecutionPolicy Bypass -File bin\install-llamacpp.ps1 -Ctx 16384
#   powershell -ExecutionPolicy Bypass -File bin\install-llamacpp.ps1 -SkipModel
#   powershell -ExecutionPolicy Bypass -File bin\install-llamacpp.ps1 -DraftFile ""
#
# ВНИМАНИЕ: как и остальные .ps1 проекта, скрипт не проверялся на Windows
# (в песочнице нет Windows). Имена файлов сборок в релизах GitHub со временем
# меняются — скрипт берёт последний релиз и выбирает asset по шаблону; если
# сборка не нашлась, он скажет, что скачать вручную.

param(
    [string]$Dir = "",                     # куда ставить (по умолчанию build\llm)
    [string]$Repo = "unsloth/gemma-4-12B-it-qat-GGUF",
    [string]$File = "gemma-4-12B-it-qat-UD-Q4_K_XL.gguf",
    [string]$DraftFile = "mtp-gemma-4-12B-it.gguf",   # "" — отключить драфтер
    [int]$Ctx = 65536,                     # контекст; расчёт под 12 ГБ — в ПЛАН §29
    [int]$Port = 8080,
    [switch]$SkipServer,
    [switch]$SkipModel
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Dir) { $Dir = Join-Path $root "build\llm" }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$models = Join-Path $Dir "models"
New-Item -ItemType Directory -Force -Path $models | Out-Null

function Get-File([string]$Url, [string]$Out) {
    if (Test-Path $Out) { Write-Host "  уже на месте: $(Split-Path $Out -Leaf)"; return $true }
    Write-Host "  качаю: $Url"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        # -C - докачивает, если соединение оборвалось на середине
        & curl.exe -L --fail --retry 3 -C - -o $Out $Url
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Out
    }
    if (Test-Path $Out) { return $true }
    Write-Host "  НЕ скачалось: $Url"
    return $false
}

Write-Host "== 1/4  llama.cpp: свежая сборка под Windows CUDA =="
if (-not $SkipServer) {
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest" `
                                 -Headers @{ "User-Agent" = "asm-installer" }
        $assets = $rel.assets | Where-Object { $_.name -match "bin-win-cuda.*x64\.zip$" -or
                                               $_.name -match "cudart-llama-bin-win-cuda.*\.zip$" }
        if (-not $assets) {
            Write-Host "  сборка win-cuda не найдена в релизе $($rel.tag_name)."
            Write-Host "  Скачайте вручную: https://github.com/ggml-org/llama.cpp/releases"
            Write-Host "  и распакуйте в: $Dir"
        } else {
            foreach ($a in $assets) {
                $zip = Join-Path $Dir $a.name
                Write-Host "  качаю $($a.name) ($([math]::Round($a.size / 1MB)) МБ)"
                if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                    & curl.exe -L --fail --retry 3 -o $zip $a.browser_download_url
                } else {
                    Invoke-WebRequest -Uri $a.browser_download_url -OutFile $zip
                }
                Expand-Archive -Path $zip -DestinationPath $Dir -Force
                Remove-Item $zip -Force
            }
        }
    } catch {
        Write-Host "  не удалось скачать автоматически: $($_.Exception.Message)"
        Write-Host "  возьмите релиз вручную: https://github.com/ggml-org/llama.cpp/releases"
    }
    $server = Get-ChildItem -Path $Dir -Recurse -Filter "llama-server.exe" -ErrorAction SilentlyContinue |
              Select-Object -First 1
    if ($server) {
        Write-Host "  llama-server: $($server.FullName)"
    } else {
        Write-Host "  ВНИМАНИЕ: llama-server.exe не найден в $Dir — положите бинарь туда вручную"
    }
} else { Write-Host "  пропущено (-SkipServer)" }

Write-Host "== 2/4  модель Gemma 4 12B it QAT (6,72 ГБ) и MTP-драфтер (254 МБ) =="
if (-not $SkipModel) {
    $base = "https://huggingface.co/$Repo/resolve/main"
    if (-not (Get-File "$base/$File" (Join-Path $models $File))) {
        Write-Host "  проверьте имена файлов: https://huggingface.co/$Repo/tree/main"
        Write-Host "  и передайте точное имя: -File <имя.gguf>"
    }
    if ($DraftFile) {
        if (-not (Get-File "$base/$DraftFile" (Join-Path $models $DraftFile))) {
            Write-Host "  драфтер не скачался — будет работать без него (медленнее)"
        }
    }
    $mmproj = Join-Path $models "mmproj-F16.gguf"
    Write-Host "  (картинки/аудио: при необходимости добавьте mmproj-F16.gguf и флаг --mmproj)"
} else { Write-Host "  пропущено (-SkipModel)" }

Write-Host "== 3/4  serve.cmd с настройками под 12 ГБ =="
$serve = Join-Path $Dir "serve.cmd"
$arr = New-Object System.Collections.Generic.List[string]
$arr.Add("@echo off")
$arr.Add("rem Запуск движка и модели. Настройки под RTX 4070 Ti 12 ГБ:")
$arr.Add("rem   -ngl 99            все слои на GPU")
$arr.Add("rem   -c $Ctx           контекст. У Gemma 4 гибридное внимание: 40 слоёв из 48")
$arr.Add("rem                     держат скользящее окно 1024 токена и не растут, кеш")
$arr.Add("rem                     растёт только у 8 глобальных слоёв — поэтому 64K стоят")
$arr.Add("rem                     ~2,2 ГиБ с q8_0, а не как у обычных моделей")
$arr.Add("rem   --cache-type-k/-v q8_0   квантованный KV-кеш: контекст вдвое компактнее")
$arr.Add("rem   -fa on             flash attention")
$arr.Add("rem   --spec-*          MTP-драфтер: быстрее, вывод не меняется (каждый")
$arr.Add("rem                     токен драфтера проверяет основная модель)")
$arr.Add("rem   --jinja           шаблон чата модели: без него не работают вызовы инструментов")
$arr.Add("rem   --host 127.0.0.1  только локально; наружу порт не выставлять")
$arr.Add("cd /d `"%~dp0`"")
$arr.Add("llama-server.exe ^")
$arr.Add("  -m `"models\$File`" ^")
if ($DraftFile) {
    $arr.Add("  -md `"models\$DraftFile`" --spec-type draft-mtp --spec-draft-n-max 4 ^")
}
$arr.Add("  --alias gemma4:12b-it-qat ^")
$arr.Add("  -ngl 99 -c $Ctx --cache-type-k q8_0 --cache-type-v q8_0 -fa on ^")
$arr.Add("  --host 127.0.0.1 --port $Port --jinja")
$arr.Add("")
$arr.Add("rem Если сборка ругается на --spec-* или -md, в свежем llama.cpp драфтер")
$arr.Add("rem подхватывается сам при загрузке по имени из Hugging Face — вариант:")
$arr.Add("rem   llama-server.exe -hf $Repo`:UD-Q4_K_XL --spec-type draft-mtp --spec-draft-n-max 4 -ngl 99 -fa on --jinja")
$arr.Add("rem")
$arr.Add("rem Расчёт под 12 ГБ: веса 6,3 + кеш 64K с q8_0 ~2,2 + буферы ~1,0 = ~9,5 ГиБ,")
$arr.Add("rem остаётся ~2,5 ГиБ запаса. 128K сюда не влезет (~11,5 ГиБ) — не поднимать.")
$arr.Add("rem Не хватает VRAM: -c 32768 (потеря ~1 ГиБ), затем -c 16384.")
$arr.Add("rem Факт, а не оценку, покажет лог llama-server: строка KV self size.")
Set-Content -Path $serve -Value $arr -Encoding OEM
Write-Host "  записан: $serve"

Write-Host "== 4/4  что вписать в проект =="
Write-Host ""
Write-Host "  Запуск движка:  $serve   (или двойным щелчком)"
Write-Host "  Проверка:       curl.exe http://127.0.0.1:$Port/v1/models"
Write-Host ""
Write-Host "  Настройки проекта (PowerShell инлайново переменные не ставит, поэтому --set):"
Write-Host ""
Write-Host "    python3 app.py --set ASM_LLM_BASE=http://127.0.0.1:$Port/v1 ^"
Write-Host "                    --set ASM_LLM_STYLE=openai ^"
Write-Host "                    --set ASM_LLM_MODEL=gemma4:12b-it-qat serve --port 8000"
Write-Host ""
Write-Host "  Замер (бенч читает настройки из окружения):"
Write-Host "    `$env:ASM_LLM_BASE=`"http://127.0.0.1:$Port/v1`""
Write-Host "    python bin\llm-bench.py"
Write-Host ""
Write-Host "  Ollama-путь остаётся запасным: powershell -File bin\install-llm.ps1"
