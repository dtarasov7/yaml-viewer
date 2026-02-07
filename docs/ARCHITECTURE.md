# Архитектура

Этот документ описывает архитектуру `yaml-viewer.py` на уровне компонентов, классов и ключевых сценариев.

## Компоненты

- **Security & Validation**
  - `validate_file_path`, `validate_yaml_object`
  - `safe_regex_compile`, `safe_regex_search`
  - `alarm_handler` / таймауты
- **YAML Parsing**
  - `simple_yaml_load` и вспомогательные парсеры YAML‑строк/скаляров
  - `split_yaml_documents` — разбиение на документы/объекты
- **Domain Model**
  - `YamlNode` — дерево YAML
  - `YamlFile` — источник/файл, даёт объекты и узлы
- **TUI**
  - `YamlTuiViewer` — состояние, отрисовка, обработка клавиш, диалоги поиска/фильтра

Диаграммы: см. `docs/diagrams/*.puml`.
