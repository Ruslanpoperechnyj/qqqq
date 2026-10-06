# Установка локальной модели для ASM.
#
# Ставит Ollama, тянет gemma4:12b-it-qat, прописывает ASM_LLM_BASE и проверяет результат.
# Запуск из PowerShell в корне проекта:
#
#     powershell -ExecutionPolicy Bypass -File bin\install-llm.ps1
#
# Ключи:
#   -Model gemma4:12b-it-qat   другая модель (например qwen3.5:9b)
#   -SkipInstall        не ставить Ollama, только модель и настройка
#
# Права администратора не нужны: Ollama ставится в профиль пользователя.

param(
    [string]$Model = "gemma4:12b-it-qat",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Installer = "https://ollama.com/download/OllamaSetup.exe"
$OllamaExe = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"

function Say($text) { Write-Host $text -ForegroundColor Cyan }
function Ok($text)  { Write-Host "  [ok] $text" -ForegroundColor Green }
function Warn($text) { Write-Host "  [!] $text" -ForegroundColor Yellow }
function Die($text) { Write-Host "  [ошибка] $text" -ForegroundColor Red; exit 1 }

Say "1/5  Ищу Ollama"

# Нормализуем в строку сразу: Get-Command даёт объект, Test-Path - строку.
# Важно для совместимости с Windows PowerShell 5.1 (без оператора ??).
$ollama = $null
$cmd = Get-Command ollama -ErrorAction SilentlyContinue
if ($cmd) { $ollama = $cmd.Source }
elseif (Test-Path $OllamaExe) { $ollama = $OllamaExe }

if ($ollama) {
    Ok "Ollama уже стоит: $ollama"
} elseif ($SkipInstall) {
    Die "Ollama не найдена, а задан -SkipInstall"
} else {
    Say "2/5  Скачиваю установщик"
    $tmp = Join-Path $env:TEMP "OllamaSetup.exe"
    try {
        Invoke-WebRequest -Uri $Installer -OutFile $tmp -UseBasicParsing
    } catch {
        Die ("не удалось скачать установщик: " + $_.Exception.Message +
             "`nСкачайте вручную с https://ollama.com/download и запустите, " +
             "затем повторите с -SkipInstall")
    }
    Ok "скачано: $tmp"

    Say "3/5  Устанавливаю (без запросов, в профиль пользователя)"
    $p = Start-Process -FilePath $tmp -ArgumentList "/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES" -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Die "установщик завершился с кодом $($p.ExitCode)"
    }
    Ok "установлено"

    if (-not (Test-Path $OllamaExe)) {
        Die "после установки файл не найден: $OllamaExe"
    }
    $ollama = $OllamaExe
}

Say "4/5  Жду, пока Ollama поднимется на 127.0.0.1:11434"

$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/version" -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 2 }
}

if (-not $ready) {
    Warn "Ollama не отвечает. Пробую запустить вручную."
    Start-Process -FilePath $ollama -ArgumentList "serve" -WindowStyle Hidden
    for ($i = 0; $i -lt 15; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/version" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Seconds 2 }
    }
}

if (-not $ready) { Die "Ollama не поднялась. Запустите 'ollama serve' вручную и повторите." }
Ok "Ollama отвечает"

Say "5/5  Качаю модель $Model (это самая долгая часть)"
& $ollama pull $Model
if ($LASTEXITCODE -ne 0) { Die "не удалось скачать модель $Model" }
Ok "модель скачана"

Say "Проверяю, что модель отвечает"
$probe = '{"model":"' + $Model + '","messages":[{"role":"user","content":"ответь одним словом: работает"}],"stream":false}'
try {
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/chat" -Method Post -Body $probe -ContentType "application/json" -TimeoutSec 180
    Ok "модель ответила: $($resp.message.content)"
} catch {
    Warn "проверочный запрос не прошёл: $($_.Exception.Message)"
}

Say "Прописываю ASM_LLM_BASE для текущего пользователя"
[Environment]::SetEnvironmentVariable("ASM_LLM_BASE", "http://localhost:11434", "User")
Ok "ASM_LLM_BASE = http://localhost:11434 (подхватится в новых окнах)"

Write-Host ""
Say "Готово. Что дальше:"
Write-Host ""
Write-Host "  В ЭТОМ окне переменная ещё не видна, задайте её вручную:"
Write-Host '    $env:ASM_LLM_BASE="http://localhost:11434"'
Write-Host ""
Write-Host "  Затем замерьте модель на задачах проекта:"
Write-Host "    python bin\llm-bench.py"
Write-Host ""
Write-Host "  Если захотите сравнить с другой моделью:"
Write-Host "    & $ollama pull qwen3.5:9b"
Write-Host "    python bin\llm-bench.py --model qwen3.5:9b"
Write-Host ""
Write-Host "  На что смотреть в выводе: симв/с (ниже 25 - агент будет тормозить)"
Write-Host "  и объём ответа (тысячи символов на задачу = модель пишет длинные"
Write-Host "  рассуждения, и каждый шаг агента будет занимать минуты)."
