# DCPM Connector:

## Архитектура и основные компоненты

- `dcpm/discovery/` — исследование источников и определение доступных способов получения данных.
- `dcpm/compiler/` — формирование планов подключения на основе доступных операций.
- `dcpm/plan/` — реестр операций и проверка планов.
- `dcpm/runtime/` — выполнение планов, получение и извлечение данных.
- `dcpm/processing/` — обработка HTML, PDF, JSON, CSV, XML и текстовых данных.
- `dcpm/semantic/` — семантический анализ, определение предметных областей, извлечение фактов, сопоставление сущностей и обработка противоречий.
- `dcpm/security/` — проверка URL, защита сетевых запросов, обработка недоверенных данных и редактирование чувствительной информации.
- `dcpm/storage/` — хранение данных и файлов.
- `dcpm/api/` — API приложения.

## Запуск

```bash
pip install flask beautifulsoup4 lxml defusedxml pypdf cryptography

python -m dcpm genkey tenantA

DCPM_API_KEYS="tenantA:<sha256>" DCPM_DATA_DIR=./data python -m dcpm serve
```

## Запуск тестов

```bash
python -m unittest discover -s tests -t .
```

## Подключение локальной модели

Пример для Ollama:

```bash
ollama pull qwen2.5:7b-instruct
ollama serve
```

Пример подключения:

```python
from dcpm.semantic.llm import LocalLLMClient, LocalLLMConfig

llm = LocalLLMClient(
    LocalLLMConfig(
        model="qwen2.5:7b-instruct",
        base_url="http://127.0.0.1:11434/v1"
    )
)
```
