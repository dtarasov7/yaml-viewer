# Changelog / История изменений

All notable changes to this project are documented in this file.
Все значимые изменения проекта документируются в этом файле.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
проект следует [Semantic Versioning](https://semver.org/lang/ru/).

## [v1.1.0] - 2026-02-27

### Added
- Value viewer mode to decode current value as Base64 (`b`).
- Automatic pretty-printing for decoded JSON payloads.
- Value viewer mode to interpret value as X.509 certificate (`c`) including Base64-wrapped input.
- Certificate details rendered via `openssl x509 -noout -text -nameopt utf8`.
- Value viewer navigation for `Home`, `End`, `PgUp`, `PgDn`.
- Dedicated footer hotkeys in value viewer.
- English/Russian keyboard-layout hotkey matching for letter shortcuts.
- Escape-sequence normalization for special keys in terminals.

### Changed
- Main-screen "expand/collapse all" hotkeys moved from `A/Z` to `x/v`.
- Global search hotkey moved to `u` (case-insensitive hotkey handling).
- Hotkey matching is now case-insensitive (CapsLock/Shift do not matter).
- Main help line updated for current keymap.

### Fixed
- `Home/End` handling in terminal mode no longer triggers unintended exit.
- Leaf-node toggle/expand flow fixed so children are built correctly.
- `Enter` -> expand/collapse flow regression fixed (including follow-up expand-all behavior).
- Multi-line OpenSSL errors normalized to one line for header rendering.
- Error state for invalid Base64/certificate input shown in value-view header.

### Добавлено
- Режим просмотра значения с декодированием Base64 (`b`).
- Автоформатирование результата, если декодированное значение является JSON.
- Режим просмотра значения как X.509 сертификата (`c`), включая Base64-обёртку.
- Вывод сертификата через `openssl x509 -noout -text -nameopt utf8`.
- Навигация в окне значения по `Home`, `End`, `PgUp`, `PgDn`.
- Отдельная строка подсказок внизу окна просмотра значения.
- Поддержка горячих клавиш в английской и русской раскладке.
- Нормализация ESC-последовательностей терминала для специальных клавиш.

### Изменено
- Горячие клавиши "развернуть/свернуть все" перенесены с `A/Z` на `x/v`.
- Глобальный поиск перенесён на `u` (из-за регистронезависимой обработки).
- Горячие клавиши теперь регистронезависимы (CapsLock/Shift не влияют).
- Обновлена нижняя строка подсказок на основном экране.

### Исправлено
- `Home/End` больше не приводят к непреднамеренному выходу.
- Исправлена логика toggle/expand для корректного построения дочерних узлов.
- Исправлена регрессия `Enter` -> expand/collapse (в том числе для expand-all).
- Многострочные ошибки OpenSSL приведены к одной строке для header.
- Ошибки при невалидном Base64/сертификате отображаются в header окна значения.

## [v1.0.0] - 2026-01-01

### Added
- Initial release.
- Interactive tree viewer for YAML files in terminal (`curses`).
- Lazy loading for large files and multi-document YAML support.
- Search and field filtering.
- Expand/collapse navigation.
- Basic safety limits and regex timeout protections.
- Error logging to `yaml-viewer.log`.

### Добавлено
- Первый публичный релиз.
- Интерактивный просмотр YAML в терминале (`curses`) в виде дерева.
- Ленивая загрузка больших файлов и поддержка multi-document YAML.
- Поиск и фильтрация полей.
- Навигация с разворачиванием/сворачиванием узлов.
- Базовые ограничения безопасности и таймауты regex.
- Логирование ошибок в `yaml-viewer.log`.
