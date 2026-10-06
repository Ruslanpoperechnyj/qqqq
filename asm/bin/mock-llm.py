#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Демонстрационная «модель» для проверки ИИ-собеседника без настоящей LLM.

Отвечает по протоколу, совместимому с OpenAI (POST /v1/chat/completions,
stream=true), и отдаёт заранее заготовленный русский разбор — этого достаточно,
чтобы увидеть, как работает поток токенов в интерфейсе.

Для настоящей модели это НЕ нужно: укажите ASM_LLM_BASE на Ollama
(http://localhost:11434) или на llama.cpp / vLLM / LM Studio.

Запуск:  python3 bin/mock-llm.py [порт]
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ANSWER = """Разбираю по данным, которые передал инструмент.

**Что это.** Этот элемент попал в периметр как отдельный сервис, и по нему уже есть находки — \
начните с тех, что помечены как эксплуатируемые в реальных атаках (KEV): по ним атака идёт без \
дополнительных условий, достаточно доступа по сети.

**Чем опасно.** Если версия компонента старая, закрывать «частично» не получится: производитель \
обычно фиксит весь класс проблем одним обновлением. До обновления любой, кто видит этот порт \
снаружи, может проверить его автоматическими сканерами — а их ходят десятки в сутки.

**Что проверить в первую очередь.**
1. Кто вообще должен иметь доступ к сервису: если только сотрудники из офиса — порт не должен \
   смотреть в интернет, это закрывается одним правилом.
2. Какая версия стоит фактически, а не какая указана в документации.
3. Есть ли в логах попытки эксплуатации за последние недели (всплеск запросов к этому порту).

**Что сделать.**
1. Обновить компонент до версии с исправлением, перезапустить службу, убедиться, что версия \
   в баннере изменилась.
2. Если обновление невозможно — ограничить доступ по IP-адресам или закрыть сервис за VPN.
3. После закрытия запустить повторный анализ: инструмент покажет, ушла ли находка из периметра.

Это демонстрационный ответ. Подключите локальную модель (например, Qwen или Dolphin через Ollama), \
и она ответит по существу именно про этот элемент."""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        # если спрашивают вердикт (триаж) — отвечаем JSON, как просит схема
        if "вердикт" in raw:
            answer = ('{"вердикт": "недостаточно данных", "уверенность": 55, '
                      '"почему": "Находка получена по версии в баннере: это признак для проверки, '
                      'а не доказательство. Противоречий в данных нет, но и активного подтверждения тоже.", '
                      '"чем_подтвердить": ["запустить активную проверку по этому адресу", '
                      '"сверить точную версию на сервере", "сопоставить с перечнем обновлений вендора"]}')
        else:
            answer = ANSWER
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def chunk(obj):
            data = ("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode()
            self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()

        for word in answer.split(" "):
            chunk({"choices": [{"delta": {"content": word + " "}}]})
            time.sleep(0.012)
        chunk({"choices": [{"delta": {}, "finish_reason": "stop"}]})
        tail = b"data: [DONE]\n\n"
        self.wfile.write(f"{len(tail):X}\r\n".encode() + tail + b"\r\n0\r\n\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11435
    print(f"демо-модель слушает 127.0.0.1:{port} (протокол OpenAI, поток)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
