# bin/install-coder-next.ps1 — Qwen3-Coder-Next (80B-A3B, 3B активных) для пробы
#
# Зачем отдельный скрипт, а не замена install-llamacpp.ps1:
#   Это НЕ замена рабочей модели. Gemma 4 12B влезает в 12 ГБ целиком и даёт
#   60-86 ток/с при TTFT 0,4 с; Qwen3-Coder-Next весит 27-36 ГБ, в 12 ГБ не
#   влезает никогда и живёт на процессоре — то есть пробник «по приколу», а не
#   боевой движок агента. Поэтому: свой порт (8081), своя папка моделей, общий
#   бинарь llama.cpp. Ничего в текущем serve.cmd не трогается.
#
# Что известно про модель (проверено по карточке и отчётам, не по слухам):
#   * 80 млрд параметров всего, ~3 млрд активных на токен (MoE, 512 экспертов,
#     10 активных + 1 общий), 48 слоёв, контекст 256K, лицензия Apache 2.0;
#   * режим только «не думающий» — рассуждений отдельным блоком не выдаёт
#     (для кодовых агентов это плюс по скорости, для планирования — минус);
#   * модель КОДОВАЯ (SWE-bench Verified ~70%, Terminal-Bench ~52%). Про
#     «божественность в ИБ» говорит только реклама: ни одного ИБ-бенчмарка в
#     карточке нет. Решать будет наш конвейер, а не впечатление.
#
# Чего ожидать по скорости на RTX 4070 Ti 12 ГБ + 32 ГБ RAM:
#   * 4 бита (Q4_K_XL, 49,6 ГБ) не влезают: 12 + 32 = 44 ГБ суммарно;
#   * рабочие варианты — UD-Q2_K_XL (26,8 ГБ) и UD-Q3_K_S (33,3 ГБ).
#     Q3_K_S уже на грани: 33,3 ГБ против 44 ГБ суммы, а Windows и KV-кеш
#     тоже хотят память — при нехватке файл начнёт читаться с диска;
#   * отчёты с машин похожего класса (8-16 ГБ видеопамяти, 32 ГБ RAM) дают
#     3-10 ток/с; на 5090+64 ГБ — 12-24 ток/с. Оценка «15-20 ток/с» на нашем
#     железе не подтверждается: упирается не в GPU, а в память процессора.
#
# Использование:
#   powershell -ExecutionPolicy Bypass -File bin\install-coder-next.ps1
#   ... -Quant UD-Q3_K_S          (если хочется качества, а не скорости)
#   ... -Quant UD-TQ1_0           (18,9 ГБ — только посмотреть, что запустится)
#   ... -CpuMoe 44                (больше экспертов на CPU, если не влезает)

param(
    [string]$Dir = "",
    [string]$Repo = "unsloth/Qwen3-Coder-Next-GGUF",
    [ValidateSet("UD-TQ1_0", "UD-Q2_K_XL", "UD-Q3_K_S", "UD-Q3_K_M", "UD-Q3_K_XL")]
    [string]$Quant = "UD-Q2_K_XL",
    [int]$Ctx = 32768,
    [int]$Port = 8081,
    [int]$CpuMoe = 40,
    [switch]$SkipModel
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Dir) { $Dir = Join-Path $root "build\llm" }
$models = Join-Path $Dir "models"
New-Item -ItemType Directory -Force -Path $models | Out-Null
$file = "Qwen3-Coder-Next-$Quant.gguf"

# Размеры файлов из карточки модели (ГБ, как показывает Hugging Face) —
# чтобы человек понимал, что качает и сколько ему потом жить с этим на диске.
$sizes = @{
    "UD-TQ1_0"   = 18.9
    "UD-Q2_K_XL" = 26.8
    "UD-Q3_K_S"  = 33.3
    "UD-Q3_K_M"  = 35.9
    "UD-Q3_K_XL" = 36.3
}

Write-Host "== 1/3  движок llama.cpp =="
$server = Get-ChildItem -Path $Dir -Recurse -Filter "llama-server.exe" -ErrorAction SilentlyContinue |
          Select-Object -First 1
if (-not $server) {
    Write-Host "  llama-server.exe в $Dir не найден."
    Write-Host "  Сначала: powershell -ExecutionPolicy Bypass -File bin\install-llamacpp.ps1"
    Write-Host "  (он качает свежую сборку; модель Gemma можно не качать: -SkipModel)"
} else {
    Write-Host "  найден: $($server.FullName)"
    Write-Host "  ВАЖНО: нужен свежий билд — флаг --n-cpu-moe и архитектура qwen3next"
    Write-Host "  появились позже; старый бинарь просто не поймёт модель."
}

Write-Host "== 2/3  модель $Quant (~$($sizes[$Quant]) ГБ) =="
if (-not $SkipModel) {
    $url = "https://huggingface.co/$Repo/resolve/main/$file"
    $out = Join-Path $models $file
    if (Test-Path $out) {
        $have = [math]::Round((Get-Item $out).Length / 1e9, 1)
        Write-Host "  уже на месте: $file ($have ГБ)"
    } else {
        Write-Host "  качаю: $url"
        Write-Host "  файл большой: обрыв связи — не беда, повторный запуск продолжит (-C -)"
        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
            & curl.exe -L --fail --retry 3 -C - -o $out $url
        } else {
            Invoke-WebRequest -Uri $url -OutFile $out
        }
        if (Test-Path $out) {
            Write-Host "  скачано: $([math]::Round((Get-Item $out).Length / 1e9, 1)) ГБ"
        } else {
            Write-Host "  НЕ скачалось. Проверьте имя файла:"
            Write-Host "  https://huggingface.co/$Repo/tree/main"
        }
    }
} else { Write-Host "  пропущено (-SkipModel)" }

Write-Host "== 3/3  serve-coder.cmd (отдельный порт, ничего общего с Gemma) =="
$serve = Join-Path $Dir "serve-coder.cmd"
$arr = New-Object System.Collections.Generic.List[string]
$arr.Add("@echo off")
$arr.Add("rem Qwen3-Coder-Next $Quant — пробник на RTX 4070 Ti 12 ГБ + 32 ГБ RAM.")
$arr.Add("rem")
$arr.Add("rem Почему так, а не как у Gemma:")
$arr.Add("rem   -ngl 99            на GPU идут внимание, эмбеддинги и общий эксперт —")
$arr.Add("rem                     они маленькие и их важно считать быстро;")
$arr.Add("rem   --n-cpu-moe $CpuMoe   эксперты первых слоёв остаются в оперативной памяти:")
$arr.Add("rem                     на токен читаются только активные (3 млрд из 80),")
$arr.Add("rem                     поэтому MoE и работает на CPU терпимо;")
$arr.Add("rem   -c $Ctx          контекст. У модели гибридное внимание (DeltaNet +")
$arr.Add("rem                     обычное), кеш растёт медленнее, чем у dense-моделей,")
$arr.Add("rem                     но 12 ГБ всё равно не резиновые: 32K разумный максимум;")
$arr.Add("rem   --jinja          шаблон чата: без него не работают вызовы инструментов")
$arr.Add("rem                     (в феврале llama.cpp как раз правил их разбор именно")
$arr.Add("rem                     для этой модели — старый билд будет врать);")
$arr.Add("rem   temp 1.0/top-p 0.95/top-k 40/min-p 0.01 — рекомендация Qwen.")
$arr.Add("rem")
$arr.Add("rem Не влезает в память (тормозит, диск молотит):")
$arr.Add("rem   увеличить --n-cpu-moe (45 — почти всё на CPU) или взять квант меньше;")
$arr.Add("rem не понимает флаг --n-cpu-moe (старый билд): заменить на --cpu-moe,")
$arr.Add("rem   а -ngl 99 на -ngl 20.")
$arr.Add("rem Мониторинг: nvidia-smi — сколько VRAM занято; в логе llama-server")
$arr.Add("rem   строка KV self size и скорость генерации.")
$arr.Add("cd /d `"%~dp0`"")
$arr.Add("llama-server.exe ^")
$arr.Add("  -m `"models\$file`" ^")
$arr.Add("  --alias qwen3-coder-next ^")
$arr.Add("  -ngl 99 --n-cpu-moe $CpuMoe ^")
$arr.Add("  -c $Ctx --cache-type-k q8_0 --cache-type-v q8_0 -fa on ^")
$arr.Add("  --temp 1.0 --top-p 0.95 --top-k 40 --min-p 0.01 ^")
$arr.Add("  --host 127.0.0.1 --port $Port --jinja")
$arr.Add("")
$arr.Add("rem Проба планов агента на этой модели (проект подключается ключами):")
$arr.Add("rem   python3 app.py --set ASM_LLM_BASE=http://127.0.0.1:$Port/v1 ^")
$arr.Add("rem                   --set ASM_LLM_STYLE=openai ^")
$arr.Add("rem                   --set ASM_LLM_MODEL=qwen3-coder-next ^")
$arr.Add("rem                   --set ASM_LLM_NUM_CTX=$Ctx agent facts 1")
$arr.Add("rem")
$arr.Add("rem Скорость и качество на НАШИХ задачах (не на бенчмарках из интернета):")
$arr.Add("rem   python3 bin/llm-bench.py --pro --repeat 2")
$arr.Add("rem   ответ модели на сложную задачу -> python3 app.py agent check 1 --file отв.txt")
Set-Content -Path $serve -Value $arr -Encoding OEM
Write-Host "  записан: $serve"
Write-Host ""
Write-Host "  Запуск:     $serve   (или двойным щелчком)"
Write-Host "  Проверка:   curl.exe http://127.0.0.1:$Port/v1/models"
Write-Host "  Ожидание:   4-10 ток/с на этой машине (12 ГБ VRAM + 32 ГБ RAM)."
Write-Host "              Если вышло больше 15 — сообщите: значит, память работает"
Write-Host "              лучше расчёта, и модель можно рассмотреть всерьёз."
