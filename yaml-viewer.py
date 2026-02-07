#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yaml-viewer.py

Консольная TUI-утилита для просмотра больших YAML файлов в виде интерактивного дерева.
Поддерживает ленивую загрузку, поиск, фильтрацию и защиту от различных DoS-атак.

Использование:
    python yaml-viewer.py file1.yaml [file2.yaml ...]
"""

import curses
import json
import os
import re
import signal
import sys
import traceback
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "1.0.0"
__author__ = "Tarasov Dmitry"


# =============================================================================
# Константы безопасности
# =============================================================================
MAX_YAML_DEPTH = 100
MAX_STRING_LENGTH = 10 * 1024 * 1024  # 10 MB
MAX_NUMBER_DIGITS = 4300
MAX_ARRAY_ITEMS = 1_000_000
MAX_OBJECT_KEYS = 100_000
MAX_EXPAND_NODES = 100_000
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB
REGEX_TIMEOUT = 2
CACHE_SIZE = 200
PRELOAD_OBJECTS = 20
LOAD_BATCH_SIZE = 5


# =============================================================================
# Логирование
# =============================================================================
# Лог-файл в текущей директории (кросс-платформенность)
LOG_FILE = Path("yaml-viewer.log").resolve()

def log_error(context: str, exception: Exception):
    """Логирует ошибку в файл с timestamp и traceback."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n{'='*80}\n")
            f.write(f"[{timestamp}] {context}\n")
            f.write(f"Exception: {type(exception).__name__}: {str(exception)}\n")
            f.write(f"{'='*80}\n")
            traceback.print_exc(file=f)
            f.write(f"{'='*80}\n\n")
    except Exception:
        pass


def log_warning(context: str, message: str):
    """Логирует предупреждение в файл."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] WARNING: {context}\n")
            f.write(f"  {message}\n\n")
    except Exception:
        pass


class SecurityError(Exception):
    """Ошибка безопасности при обработке данных."""
    pass


class TimeoutError(Exception):
    """Таймаут выполнения операции."""
    pass


class YamlParseError(Exception):
    """Ошибка парсинга YAML."""
    pass


def validate_file_path(filepath: str) -> Path:
    """
    Проверяет и нормализует путь к файлу.
    Запрещает чтение псевдо-устройств и системных файлов.
    """
    try:
        path = Path(filepath).resolve()
    except Exception as e:
        raise SecurityError(f"Некорректный путь: {e}")

    if not path.exists():
        raise SecurityError(f"Файл не существует: {path}")

    if not path.is_file():
        raise SecurityError(f"Путь не является обычным файлом: {path}")

    # Запрет на псевдо-устройства и системные файлы (только для Unix)
    if sys.platform != 'win32':
        path_str = str(path)
        forbidden_prefixes = ['/dev/', '/proc/', '/sys/']
        for prefix in forbidden_prefixes:
            if path_str.startswith(prefix):
                raise SecurityError(f"Запрещено чтение из {prefix}: {path}")

    # Проверка размера файла
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            raise SecurityError(f"Файл слишком большой: {size} байт (макс {MAX_FILE_SIZE})")
    except Exception as e:
        raise SecurityError(f"Не удалось получить размер файла: {e}")

    return path


def validate_yaml_object(obj: Any, depth: int = 0, path: str = "root") -> None:
    """
    Рекурсивно проверяет YAML объект на опасные конструкции.
    Выбрасывает SecurityError при обнаружении угроз.
    """
    if depth > MAX_YAML_DEPTH:
        raise SecurityError(f"Превышена максимальная глубина вложенности ({MAX_YAML_DEPTH}) в {path}")

    if isinstance(obj, str):
        if len(obj) > MAX_STRING_LENGTH:
            raise SecurityError(f"Строка слишком длинная ({len(obj)} символов) в {path}")

    elif isinstance(obj, (int, float)):
        num_str = str(obj)
        if len(num_str) > MAX_NUMBER_DIGITS:
            raise SecurityError(f"Число содержит слишком много цифр ({len(num_str)}) в {path}")

    elif isinstance(obj, list):
        if len(obj) > MAX_ARRAY_ITEMS:
            raise SecurityError(f"Массив содержит слишком много элементов ({len(obj)}) в {path}")
        for i, item in enumerate(obj):
            validate_yaml_object(item, depth + 1, f"{path}[{i}]")

    elif isinstance(obj, dict):
        if len(obj) > MAX_OBJECT_KEYS:
            raise SecurityError(f"Объект содержит слишком много ключей ({len(obj)}) в {path}")
        for key, value in obj.items():
            validate_yaml_object(value, depth + 1, f"{path}.{key}")


def alarm_handler(signum, frame):
    """Обработчик сигнала таймаута."""
    raise TimeoutError("Операция превысила лимит времени")


def safe_regex_compile(pattern_str: str, timeout: int = REGEX_TIMEOUT) -> Optional[re.Pattern]:
    """
    Компилирует regex с таймаутом.
    Возвращает None при ошибке или таймауте.
    """
    try:
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(timeout)

        pattern = re.compile(pattern_str, re.IGNORECASE)

        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)

        return pattern
    except TimeoutError:
        return None
    except Exception:
        return None
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


def safe_regex_search(pattern: Optional[re.Pattern], text: str, 
                     pattern_str: str = "", timeout: int = REGEX_TIMEOUT) -> bool:
    """
    Безопасный поиск по regex с таймаутом и обрезкой длинных строк.
    """
    if len(text) > 10000:
        text = text[:10000]

    if pattern is None:
        return pattern_str.lower() in text.lower()

    try:
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(timeout)

        result = pattern.search(text) is not None

        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)

        return result
    except TimeoutError:
        return pattern_str.lower() in text.lower()
    except Exception:
        return False
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


def simple_yaml_load(text: str) -> Any:
    lines = text.strip().split('\n')
    result, _ = _parse_yaml_lines(lines, 0)
    return result


def _parse_block_scalar(lines: List[str], line_idx: int, base_indent: int, block_style: str) -> str:
    block_lines = []
    i = line_idx + 1
    block_indent = None

    while i < len(lines):
        next_line = lines[i]
        next_stripped = next_line.lstrip()

        if not next_stripped:
            block_lines.append('')
            i += 1
            continue

        next_indent = len(next_line) - len(next_stripped)

        if next_stripped.startswith('#') and next_indent <= base_indent:
            break

        if block_indent is None:
            block_indent = next_indent

        if next_indent <= base_indent:
            break

        if next_indent >= block_indent:
            block_lines.append(next_line[block_indent:].rstrip())
        else:
            block_lines.append(next_stripped.rstrip())

        i += 1

    if block_style.startswith('>'):
        paragraphs = []
        current_para = []

        for line in block_lines:
            if not line:
                if current_para:
                    paragraphs.append(' '.join(current_para))
                    current_para = []
                paragraphs.append('')
            else:
                current_para.append(line)

        if current_para:
            paragraphs.append(' '.join(current_para))

        result = '\n'.join(paragraphs)
    else:
        result = '\n'.join(block_lines)

    if block_style.endswith('-'):
        result = result.rstrip('\n')
    elif block_style.endswith('+'):
        pass
    else:
        result = result.rstrip('\n')

    return result


def _is_block_scalar_indicator(text: str) -> bool:
    text = text.strip()
    if not text:
        return False

    if text[0] not in ('|', '>'):
        return False

    if len(text) == 1:
        return True

    for char in text[1:]:
        if char not in ('+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
            return False

    return True


def _parse_yaml_lines(lines: List[str], start_idx: int, parent_indent: int = -1) -> Tuple[Any, int]:
    result = {}
    i = start_idx
    is_list_context = False

    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        if not stripped or stripped.startswith('#') or stripped == '---':
            i += 1
            continue

        indent = len(line) - len(stripped)

        if parent_indent >= 0 and indent <= parent_indent:
            break

        if stripped.startswith('- '):
            if not is_list_context:
                if result and not isinstance(result, list):
                    break
                result = []
                is_list_context = True

            item_text = stripped[2:].strip()

            if ':' in item_text and not item_text.startswith('"') and not item_text.startswith("'"):
                sub_dict = {}
                parts = item_text.split(':', 1)
                key = parts[0].strip().strip('"').strip("'")
                value_text = parts[1].strip() if len(parts) > 1 else ''

                if value_text:
                    sub_dict[key] = _parse_yaml_value(value_text)
                else:
                    sub_result, next_i = _parse_yaml_lines(lines, i + 1, indent + 2)
                    sub_dict[key] = sub_result
                    i = next_i
                    result.append(sub_dict)
                    continue

                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    next_stripped = next_line.lstrip()
                    if not next_stripped or next_stripped.startswith('#'):
                        i += 1
                        continue
                    next_indent = len(next_line) - len(next_stripped)

                    if next_indent <= indent:
                        break

                    if next_indent == indent + 2 and ':' in next_stripped and not next_stripped.startswith('- '):
                        parts = next_stripped.split(':', 1)
                        k = parts[0].strip().strip('"').strip("'")
                        v_text = parts[1].strip() if len(parts) > 1 else ''

                        if _is_block_scalar_indicator(v_text):
                            sub_dict[k] = _parse_block_scalar(lines, i, next_indent, v_text)
                            i += 1
                            while i < len(lines):
                                check_line = lines[i]
                                check_stripped = check_line.lstrip()
                                if not check_stripped:
                                    i += 1
                                    continue
                                check_indent = len(check_line) - len(check_stripped)
                                if check_indent <= next_indent:
                                    break
                                i += 1
                        elif not v_text:
                            sub_val, next_i = _parse_yaml_lines(lines, i + 1, next_indent)
                            sub_dict[k] = sub_val
                            i = next_i
                        else:
                            sub_dict[k] = _parse_yaml_value(v_text)
                            i += 1
                    else:
                        break

                result.append(sub_dict)
            else:
                if item_text:
                    value_lines = [item_text]
                    i += 1
                    while i < len(lines):
                        next_line = lines[i]
                        next_stripped = next_line.lstrip()
                        if not next_stripped:
                            i += 1
                            continue
                        next_indent = len(next_line) - len(next_stripped)

                        if next_stripped.startswith('- ') or next_indent <= indent:
                            break

                        value_lines.append(next_stripped)
                        i += 1

                    if len(value_lines) == 1:
                        result.append(_parse_yaml_value(value_lines[0]))
                    else:
                        result.append('\n'.join(value_lines))
                else:
                    result.append(None)
                    i += 1

        elif ':' in stripped and not is_list_context:
            parts = stripped.split(':', 1)
            key = parts[0].strip().strip('"').strip("'")
            value_text = parts[1].strip() if len(parts) > 1 else ''

            if _is_block_scalar_indicator(value_text):
                result[key] = _parse_block_scalar(lines, i, indent, value_text)
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    next_stripped = next_line.lstrip()
                    if not next_stripped:
                        i += 1
                        continue
                    next_indent = len(next_line) - len(next_stripped)
                    if next_indent <= indent:
                        break
                    i += 1

            elif not value_text:
                if i + 1 < len(lines):
                    temp_i = i + 1
                    while temp_i < len(lines):
                        temp_line = lines[temp_i]
                        temp_stripped = temp_line.lstrip()
                        if temp_stripped and not temp_stripped.startswith('#'):
                            break
                        temp_i += 1

                    if temp_i < len(lines):
                        next_line = lines[temp_i]
                        next_stripped = next_line.lstrip()
                        next_indent = len(next_line) - len(next_stripped)

                        if next_stripped.startswith('- '):
                            expected_indent = next_indent

                            list_items = []
                            list_i = temp_i

                            while list_i < len(lines):
                                list_line = lines[list_i]
                                list_stripped = list_line.lstrip()

                                if not list_stripped or list_stripped.startswith('#'):
                                    list_i += 1
                                    continue

                                list_indent = len(list_line) - len(list_stripped)

                                if list_stripped.startswith('- '):
                                    if list_indent != expected_indent:
                                        error_msg = f"Некорректный отступ элемента списка в строке {list_i + 1}: ожидается {expected_indent}, получено {list_indent}"
                                        log_warning("YAML parse", error_msg)
                                        raise YamlParseError(error_msg)

                                    item_text = list_stripped[2:].strip()
                                    list_items.append(_parse_yaml_value(item_text) if item_text else None)
                                    list_i += 1

                                elif list_stripped.startswith('-') and len(list_stripped) > 1 and list_stripped[1] != ' ':
                                    error_msg = f"Синтаксическая ошибка YAML в строке {list_i + 1}: элемент списка должен быть '- item', а не '-item' (отсутствует пробел после дефиса)"
                                    log_warning("YAML parse", error_msg)
                                    raise YamlParseError(error_msg)

                                elif list_indent <= indent:
                                    break
                                else:
                                    list_i += 1

                            result[key] = list_items
                            i = list_i
                            continue

                sub_result, next_i = _parse_yaml_lines(lines, i + 1, indent)
                result[key] = sub_result
                i = next_i
            else:
                result[key] = _parse_yaml_value(value_text)
                i += 1
        else:
            i += 1

    return result, i


def _parse_yaml_value(text: str) -> Any:
    text = text.strip()

    if text in ('null', 'Null', 'NULL', '~', ''):
        return None

    if text in ('true', 'True', 'TRUE'):
        return True
    if text in ('false', 'False', 'FALSE'):
        return False

    if (text.startswith('"') and text.endswith('"')) or        (text.startswith("'") and text.endswith("'")):
        return text[1:-1]

    try:
        if '.' in text or 'e' in text.lower():
            return float(text)
        return int(text)
    except ValueError:
        pass

    return text


def split_yaml_documents(filepath: Path) -> List[Tuple[int, int]]:
    documents = []
    start_line = 0

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == '---':
            if i > start_line:
                documents.append((start_line, i - 1))
            start_line = i + 1

    if start_line < len(lines):
        documents.append((start_line, len(lines) - 1))

    return documents if documents else [(0, len(lines) - 1)]


def wrap_text(text: str, width: int, indent: int = 0) -> List[str]:
    if width <= indent:
        return [text[:width]]

    result = []
    remaining = text
    first_line = True

    while remaining:
        if first_line:
            line_width = width
            first_line = False
        else:
            line_width = width - indent

        if len(remaining) <= line_width:
            if result:
                result.append(' ' * indent + remaining)
            else:
                result.append(remaining)
            break

        cut_pos = line_width
        space_pos = remaining[:line_width].rfind(' ')
        if space_pos > line_width // 2:
            cut_pos = space_pos

        if result:
            result.append(' ' * indent + remaining[:cut_pos])
        else:
            result.append(remaining[:cut_pos])

        remaining = remaining[cut_pos:].lstrip()

    return result


# =============================================================================
# Узел YAML дерева
# =============================================================================
class YamlNode:
    def __init__(self, key: str, value: Any, parent: Optional['YamlNode'] = None, 
                 record_idx: Optional[int] = None, file_idx: Optional[int] = None,
                 global_idx: Optional[int] = None):
        self.key = key
        self.value = value
        self.parent = parent
        self.record_idx = record_idx
        self.file_idx = file_idx
        self.global_idx = global_idx
        self.children: List['YamlNode'] = []
        self.expanded = False
        self.is_leaf = not isinstance(value, (dict, list)) or (isinstance(value, (dict, list)) and len(value) == 0)
        self.has_error = isinstance(value, dict) and '_error' in value

    def toggle(self):
        if not self.is_leaf:
            self.expanded = not self.expanded
            if self.expanded:
                self.expand()

    def expand(self):
        if self.is_leaf or self.expanded:
            return

        self.expanded = True
        self.children.clear()

        if isinstance(self.value, dict):
            for k, v in self.value.items():
                child = YamlNode(str(k), v, parent=self)
                self.children.append(child)
        elif isinstance(self.value, list):
            for i, item in enumerate(self.value):
                child = YamlNode("", item, parent=self)
                self.children.append(child)

    def collapse(self):
        self.expanded = False

    def expand_all(self, node_counter: List[int], max_nodes: int = MAX_EXPAND_NODES):
        if self.is_leaf:
            return

        if node_counter[0] > max_nodes:
            raise SecurityError(f"Превышен лимит узлов при развертывании ({max_nodes})")

        if not self.expanded:
            self.expand()
            node_counter[0] += len(self.children)

        for child in self.children:
            child.expand_all(node_counter, max_nodes)

    def collapse_all(self):
        self.collapse()
        for child in self.children:
            child.collapse_all()

    def get_path(self) -> List[str]:
        path = []
        node = self
        while node.parent is not None:
            if node.key:
                path.append(node.key)
            node = node.parent
        return list(reversed(path))

    def find_by_path(self, path: List[str]) -> Optional['YamlNode']:
        if not path:
            return self

        if not self.expanded:
            self.expand()

        for child in self.children:
            if child.key == path[0]:
                return child.find_by_path(path[1:])

        return None

    def display_text(self, width: int, wrap_mode: bool = False) -> List[str]:
        prefix = ""

        if self.global_idx is not None:
            prefix = f"[{self.global_idx}] "

        if self.parent and isinstance(self.parent.value, list):
            if self.is_leaf:
                text = f"- {self._format_value()}"
            else:
                if isinstance(self.value, dict):
                    text = f"- {{...}} ({len(self.value)} keys)"
                else:
                    text = f"- [...] ({len(self.value)} items)"
        else:
            if self.is_leaf:
                text = f"{prefix}{self.key}: {self._format_value()}"
            else:
                if isinstance(self.value, dict):
                    text = f"{prefix}{self.key} {{...}} ({len(self.value)} keys)"
                else:
                    text = f"{prefix}{self.key} [...] ({len(self.value)} items)"

        if wrap_mode:
            if len(text) > width:
                if self.parent and isinstance(self.parent.value, list):
                    indent = 2
                elif self.key:
                    indent = len(prefix) + len(self.key) + 2
                else:
                    indent = len(prefix)

                return wrap_text(text, width, indent)
            else:
                return [text]
        else:
            if len(text) > width:
                text = text[:width - 3] + "..."
            return [text]

    def _format_value(self) -> str:
        if self.value is None:
            return "null"
        elif isinstance(self.value, bool):
            return "true" if self.value else "false"
        elif isinstance(self.value, str):
            first_line = self.value.split('\n')[0]
            if len(self.value.split('\n')) > 1:
                if len(first_line) > 80:
                    return f'"{first_line[:80]}..." (multiline)'
                return f'"{first_line}" (multiline)'
            else:
                if len(self.value) > 100:
                    return f'"{self.value[:100]}..."'
                return f'"{self.value}"'
        else:
            return str(self.value)


class YamlFile:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.is_multi_document = False
        self.documents: List[Tuple[int, int]] = []
        self.cache: OrderedDict[int, Any] = OrderedDict()
        self.single_object: Optional[Any] = None
        self.file_lines: Optional[List[str]] = None
        self.has_parse_error = False
        self.parse_error_message = ""

        self._detect_file_type()

    def _detect_file_type(self):
        with open(self.filepath, 'r', encoding='utf-8', errors='replace') as f:
            self.file_lines = f.readlines()

        for line in self.file_lines:
            if line.strip() == '---':
                self.is_multi_document = True
                break

        if self.is_multi_document:
            self.documents = split_yaml_documents(self.filepath)
        else:
            content = ''.join(self.file_lines)

            try:
                self.single_object = simple_yaml_load(content)
                validate_yaml_object(self.single_object)
            except SecurityError as e:
                log_error(f"Security error in {self.filepath}", e)
                self.has_parse_error = True
                self.parse_error_message = str(e)
                self.single_object = {
                    "_error": f"Ошибка безопасности: {str(e)}",
                    "_file": str(self.filepath)
                }
            except YamlParseError as e:
                log_error(f"YAML parse error in {self.filepath}", e)
                self.has_parse_error = True
                self.parse_error_message = str(e)
                self.single_object = {
                    "_error": f"Ошибка парсинга YAML: {str(e)}",
                    "_file": str(self.filepath)
                }
            except Exception as e:
                log_error(f"Unexpected error parsing {self.filepath}", e)
                self.has_parse_error = True
                self.parse_error_message = str(e)
                self.single_object = {
                    "_error": f"Ошибка парсинга: {str(e)}",
                    "_file": str(self.filepath)
                }

    def __len__(self) -> int:
        if self.is_multi_document:
            return len(self.documents)
        return 1

    def __getitem__(self, index: int) -> Any:
        if not self.is_multi_document:
            return self.single_object

        if index < 0 or index >= len(self.documents):
            raise IndexError(f"Индекс {index} вне диапазона")

        if index in self.cache:
            self.cache.move_to_end(index)
            return self.cache[index]

        start_line, end_line = self.documents[index]
        lines = self.file_lines[start_line:end_line + 1]
        content = ''.join(lines)

        try:
            obj = simple_yaml_load(content)
            validate_yaml_object(obj, path=f"document[{index}]")
        except SecurityError as e:
            log_error(f"Security error in {self.filepath} document {index}", e)
            obj = {"_error": f"Объект {index} пропущен (безопасность): {str(e)}"}
        except YamlParseError as e:
            log_error(f"YAML parse error in {self.filepath} document {index}", e)
            obj = {"_error": f"Ошибка парсинга YAML в объекте {index}: {str(e)}"}
        except Exception as e:
            log_error(f"Error parsing {self.filepath} document {index}", e)
            obj = {"_error": f"Ошибка парсинга объекта {index}: {str(e)}"}

        self.cache[index] = obj
        self.cache.move_to_end(index)

        while len(self.cache) > CACHE_SIZE:
            self.cache.popitem(last=False)

        return obj


class YamlTuiViewer:
    def __init__(self, stdscr, yaml_files: List[YamlFile]):
        self.stdscr = stdscr
        self.yaml_files = yaml_files

        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_WHITE, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)

        self.root = YamlNode("root", {}, None)
        self.flat_list: List[Tuple[YamlNode, int, List[str]]] = []
        self.cursor_pos = 0
        self.scroll_offset = 0
        self.status_message = ""
        self.filter_fields: Optional[Set[str]] = None
        self.search_results: List[YamlNode] = []
        self.search_result_idx = -1
        self.loaded_objects: Dict[Tuple[int, int], bool] = {}
        self.total_objects = sum(len(f) for f in yaml_files)
        self.wrap_mode = False
        self.error_count = sum(1 for f in yaml_files if f.has_parse_error)

        self._initial_load()
        self._rebuild_flat_list()

    def _initial_load(self):
        global_idx = 0
        for file_idx, yaml_file in enumerate(self.yaml_files):
            count = min(PRELOAD_OBJECTS, len(yaml_file))
            for obj_idx in range(count):
                self._load_object(file_idx, obj_idx, global_idx)
                global_idx += 1

    def _load_object(self, file_idx: int, obj_idx: int, global_idx: int):
        key = (file_idx, obj_idx)
        if key in self.loaded_objects:
            return

        yaml_file = self.yaml_files[file_idx]
        if obj_idx >= len(yaml_file):
            return

        obj = yaml_file[obj_idx]

        filename = yaml_file.filepath.name
        if len(self.yaml_files) == 1:
            node_name = f"Document {global_idx}"
        else:
            node_name = f"{filename}:{obj_idx}"

        node = YamlNode(node_name, obj, parent=self.root, record_idx=obj_idx, 
                       file_idx=file_idx, global_idx=global_idx)
        self.root.children.append(node)
        self.loaded_objects[key] = True

    def _load_more_objects(self, count: int = LOAD_BATCH_SIZE):
        loaded = 0
        global_idx = len(self.loaded_objects)

        for file_idx, yaml_file in enumerate(self.yaml_files):
            for obj_idx in range(len(yaml_file)):
                key = (file_idx, obj_idx)
                if key not in self.loaded_objects:
                    self._load_object(file_idx, obj_idx, global_idx)
                    global_idx += 1
                    loaded += 1
                    if loaded >= count:
                        return

    def _rebuild_flat_list(self):
        self.flat_list.clear()
        height, width = self.stdscr.getmaxyx()

        for child in self.root.children:
            self._add_to_flat_list(child, 0, width - 1)

        if len(self.loaded_objects) < self.total_objects:
            list_height = height - 4
            if len(self.flat_list) == 0 or self.cursor_pos >= len(self.flat_list) - list_height:
                self._load_more_objects()
                loaded_nodes = set((n.file_idx, n.record_idx) for n, _, _ in self.flat_list if n.record_idx is not None)
                for child in self.root.children:
                    if (child.file_idx, child.record_idx) not in loaded_nodes:
                        self._add_to_flat_list(child, 0, width - 1)

    def _add_to_flat_list(self, node: YamlNode, depth: int, width: int):
        if self.filter_fields is None or self._should_show_node(node):
            indent_width = depth * 2
            available_width = width - indent_width
            wrapped_lines = node.display_text(available_width, self.wrap_mode)
            self.flat_list.append((node, depth, wrapped_lines))

        if node.expanded:
            for child in node.children:
                self._add_to_flat_list(child, depth + 1, width)

    def _should_show_node(self, node: YamlNode) -> bool:
        if self.filter_fields is None:
            return True

        if node.record_idx is not None:
            return True

        if node.is_leaf:
            return node.key in self.filter_fields

        return self._has_matching_leaf(node)

    def _has_matching_leaf(self, node: YamlNode) -> bool:
        if node.is_leaf:
            return node.key in self.filter_fields

        was_expanded = node.expanded
        if not node.expanded:
            node.expand()

        result = any(self._has_matching_leaf(child) for child in node.children)

        if not was_expanded:
            node.collapse()

        return result

    def _ensure_cursor_visible(self):
        """Обеспечивает видимость курсора на экране."""
        height = self.stdscr.getmaxyx()[0] - 4

        if self.cursor_pos < self.scroll_offset:
            self.scroll_offset = self.cursor_pos
        elif self.cursor_pos >= self.scroll_offset + height:
            self.scroll_offset = self.cursor_pos - height + 1

    def run(self):
        while True:
            self._draw()

            try:
                key = self.stdscr.getch()
            except KeyboardInterrupt:
                break

            if not self._handle_key(key):
                break

    def _draw(self):
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        if len(self.yaml_files) == 1:
            filename = self.yaml_files[0].filepath.name
            header = f"{filename} | Объектов: {self.total_objects} | Загружено: {len(self.loaded_objects)}"
        else:
            header = f"Файлов: {len(self.yaml_files)} | Объектов: {self.total_objects} | Загружено: {len(self.loaded_objects)}"

        if self.error_count > 0:
            header += f" | Ошибок: {self.error_count}"

        filter_indicator = " [FILTER]" if self.filter_fields else ""
        wrap_indicator = " [WRAP]" if self.wrap_mode else ""
        header += filter_indicator + wrap_indicator

        try:
            self.stdscr.addnstr(0, 0, header, width - 1, curses.color_pair(2) | curses.A_BOLD)
        except:
            pass

        list_height = height - 4
        y = 1
        items_shown = 0
        skip_items = self.scroll_offset

        for node, depth, wrapped_lines in self.flat_list:
            if skip_items > 0:
                skip_items -= 1
                continue

            if y >= height - 3:
                break

            indent = "  " * depth

            for line_idx, line in enumerate(wrapped_lines):
                if y >= height - 3:
                    break

                text = indent + line if line_idx == 0 else indent + line

                is_selected = items_shown == self.cursor_pos - self.scroll_offset and line_idx == 0

                if is_selected:
                    attr = curses.color_pair(1)
                elif node.has_error:
                    attr = curses.color_pair(5) | curses.A_BOLD
                elif not node.is_leaf and not node.expanded:
                    attr = curses.color_pair(4) | curses.A_BOLD
                else:
                    attr = 0

                try:
                    self.stdscr.addnstr(y, 0, text, width - 1, attr)
                except:
                    pass
                y += 1

            items_shown += 1

        status_y = height - 3
        pos_info = f"Позиция: {self.cursor_pos + 1}/{len(self.flat_list)}"
        if self.search_results:
            pos_info += f" | Результатов: {len(self.search_results)} ({self.search_result_idx + 1})"
        try:
            self.stdscr.addnstr(status_y, 0, pos_info, width - 1, curses.color_pair(3))
        except:
            pass

        if self.status_message:
            try:
                self.stdscr.addnstr(status_y + 1, 0, self.status_message[:width - 1], width - 1)
            except:
                pass

        help_text = "q:выход | ↑↓←→/hjkl:навиг | n/p:страница | Enter:откр | w:wrap | s:поиск | f:фильтр | a/z:разв/свер"
        try:
            self.stdscr.addnstr(height - 1, 0, help_text[:width - 1], width - 1)
        except:
            pass

        self.stdscr.refresh()

    def _handle_key(self, key: int) -> bool:
        if key in (ord('q'), ord('Q'), 27):
            return False

        elif key in (curses.KEY_UP, ord('k')):
            self._move_cursor(-1)
        elif key in (curses.KEY_DOWN, ord('j')):
            self._move_cursor(1)

        # Постраничная навигация
        elif key == ord('n'):  # Page Down
            self._page_down()
        elif key == ord('p'):  # Page Up
            self._page_up()

        elif key in (curses.KEY_RIGHT, ord('l')):
            self._expand_current()
        elif key == curses.KEY_LEFT:
            self._collapse_current()

        elif key in (curses.KEY_ENTER, 10, 13):
            self._handle_enter()

        elif key in (ord('w'), ord('W')):
            self._toggle_wrap()

        elif key == ord('a'):
            self._expand_current_object()
        elif key == ord('z'):
            self._collapse_current_object()

        elif key == ord('A'):
            self._expand_all_loaded()
        elif key == ord('Z'):
            self._collapse_all()

        elif key == ord('g'):
            self._goto_object()
        elif key == curses.KEY_HOME:
            self._goto_first_object()
        elif key == curses.KEY_END:
            self._goto_last_object()
        elif key == curses.KEY_NPAGE:
            self._next_object()
        elif key == curses.KEY_PPAGE:
            self._prev_object()

        elif key == ord('s'):
            self._search_current_field()
        elif key == ord('F'):
            self._global_search()

        elif key == ord('f'):
            self._filter_dialog()

        return True

    def _page_down(self):
        """ Перемещение на страницу вниз."""
        if not self.flat_list:
            return

        height = self.stdscr.getmaxyx()[0] - 4
        new_pos = min(self.cursor_pos + height, len(self.flat_list) - 1)

        if new_pos != self.cursor_pos:
            self.cursor_pos = new_pos
            self._ensure_cursor_visible()

            if self.cursor_pos >= len(self.flat_list) - height:
                if len(self.loaded_objects) < self.total_objects:
                    self._load_more_objects()
                    self._rebuild_flat_list()

    def _page_up(self):
        """Перемещение на страницу вверх."""
        if not self.flat_list:
            return

        height = self.stdscr.getmaxyx()[0] - 4
        new_pos = max(self.cursor_pos - height, 0)

        if new_pos != self.cursor_pos:
            self.cursor_pos = new_pos
            self._ensure_cursor_visible()

    def _toggle_wrap(self):
        self.wrap_mode = not self.wrap_mode
        current_node = None
        if self.flat_list and 0 <= self.cursor_pos < len(self.flat_list):
            current_node, _, _ = self.flat_list[self.cursor_pos]

        self._rebuild_flat_list()

        if current_node:
            for i, (node, _, _) in enumerate(self.flat_list):
                if node == current_node:
                    self.cursor_pos = i
                    self._ensure_cursor_visible()
                    break

        self.status_message = "Режим wrap включен" if self.wrap_mode else "Режим wrap выключен"

    def _move_cursor(self, delta: int):
        if not self.flat_list:
            return

        new_pos = self.cursor_pos + delta
        new_pos = max(0, min(new_pos, len(self.flat_list) - 1))

        if new_pos != self.cursor_pos:
            self.cursor_pos = new_pos
            self._ensure_cursor_visible()

            height = self.stdscr.getmaxyx()[0] - 4
            if self.cursor_pos >= len(self.flat_list) - height:
                if len(self.loaded_objects) < self.total_objects:
                    self._load_more_objects()
                    self._rebuild_flat_list()

    def _expand_current(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]
        if not node.is_leaf:
            node.expand()
            self._rebuild_flat_list()
            self._ensure_cursor_visible()

    def _collapse_current(self):
        """Улучшенное сворачивание с автоматическим переходом к родителю."""
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]

        if node.expanded:
            # Если текущий узел развернут - сворачиваем его
            node.collapse()
            self._rebuild_flat_list()
            self._ensure_cursor_visible()
        elif node.parent and node.parent != self.root:
            # Если текущий узел свернут - переходим к родителю
            # Сначала сворачиваем родителя, если он развернут
            if node.parent.expanded:
                node.parent.collapse()
                self._rebuild_flat_list()

            # Находим родителя в списке и перемещаем курсор
            for i, (n, _, _) in enumerate(self.flat_list):
                if n == node.parent:
                    self.cursor_pos = i
                    self._ensure_cursor_visible()
                    break

    def _handle_enter(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]

        if node.is_leaf:
            self._view_value(node)
        else:
            node.toggle()
            self._rebuild_flat_list()
            self._ensure_cursor_visible()

    def _view_value(self, node: YamlNode):
        value_str = str(node.value) if node.value is not None else "null"
        lines = value_str.split('\n')

        height, width = self.stdscr.getmaxyx()
        offset_y = 0
        offset_x = 0
        view_wrap_mode = self.wrap_mode

        while True:
            self.stdscr.clear()

            key_name = node.key if node.key else "list item"
            wrap_indicator = " [WRAP]" if view_wrap_mode else ""
            header = f"Просмотр: {key_name}{wrap_indicator} | q/Esc:закрыть | ↑↓←→:прокрутка | w:wrap"
            try:
                self.stdscr.addnstr(0, 0, header[:width - 1], width - 1, curses.color_pair(2) | curses.A_BOLD)
            except:
                pass

            view_height = height - 2

            if view_wrap_mode:
                wrapped_lines = []
                for line in lines:
                    if len(line) > width - 1:
                        wrapped_lines.extend(wrap_text(line, width - 1, 0))
                    else:
                        wrapped_lines.append(line)

                display_lines = wrapped_lines
            else:
                display_lines = lines

            for i in range(view_height):
                line_idx = offset_y + i
                if line_idx >= len(display_lines):
                    break

                line = display_lines[line_idx]
                if not view_wrap_mode:
                    line = line[offset_x:offset_x + width - 1]

                try:
                    self.stdscr.addnstr(i + 1, 0, line, width - 1)
                except:
                    pass

            self.stdscr.refresh()

            key = self.stdscr.getch()

            if key in (ord('q'), ord('Q'), 27):
                break
            elif key in (ord('w'), ord('W')):
                view_wrap_mode = not view_wrap_mode
                offset_y = 0
                offset_x = 0
            elif key == curses.KEY_UP:
                offset_y = max(0, offset_y - 1)
            elif key == curses.KEY_DOWN:
                max_lines = len(wrapped_lines if view_wrap_mode else lines)
                offset_y = min(max(0, max_lines - view_height), offset_y + 1)
            elif key == curses.KEY_LEFT and not view_wrap_mode:
                offset_x = max(0, offset_x - 1)
            elif key == curses.KEY_RIGHT and not view_wrap_mode:
                offset_x += 1

    def _expand_current_object(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]

        while node.parent != self.root and node.parent is not None:
            node = node.parent

        try:
            node_counter = [0]
            node.expand_all(node_counter)
            self._rebuild_flat_list()
            self._ensure_cursor_visible()
            self.status_message = f"Развернуто узлов: {node_counter[0]}"
        except SecurityError as e:
            self.status_message = f"Ошибка: {str(e)}"

    def _collapse_current_object(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]

        while node.parent != self.root and node.parent is not None:
            node = node.parent

        node.collapse_all()
        root_node = node

        self._rebuild_flat_list()

        for i, (n, _, _) in enumerate(self.flat_list):
            if n == root_node:
                self.cursor_pos = i
                self._ensure_cursor_visible()
                break

        self.status_message = "Объект свернут"

    def _expand_all_loaded(self):
        try:
            node_counter = [0]
            for child in self.root.children:
                child.expand_all(node_counter)
            self._rebuild_flat_list()
            self._ensure_cursor_visible()
            self.status_message = f"Развернуто узлов: {node_counter[0]}"
        except SecurityError as e:
            self.status_message = f"Ошибка: {str(e)}"

    def _collapse_all(self):
        for child in self.root.children:
            child.collapse_all()
        self._rebuild_flat_list()
        self._ensure_cursor_visible()
        self.status_message = "Все объекты свернуты"

    def _goto_object(self):
        obj_num_str = self._input_string("Номер объекта (глобальный): ")
        if not obj_num_str:
            return

        try:
            global_idx = int(obj_num_str)
            if global_idx < 0 or global_idx >= self.total_objects:
                self.status_message = f"Объект {global_idx} не существует"
                return

            current = 0
            target_file_idx = 0
            target_obj_idx = 0

            for file_idx, yaml_file in enumerate(self.yaml_files):
                if current + len(yaml_file) > global_idx:
                    target_file_idx = file_idx
                    target_obj_idx = global_idx - current
                    break
                current += len(yaml_file)

            key = (target_file_idx, target_obj_idx)
            if key not in self.loaded_objects:
                self._load_object(target_file_idx, target_obj_idx, global_idx)
                self._rebuild_flat_list()

            for i, (node, _, _) in enumerate(self.flat_list):
                if node.global_idx == global_idx:
                    self.cursor_pos = i
                    self._ensure_cursor_visible()
                    break
        except ValueError:
            self.status_message = "Некорректный номер"

    def _goto_first_object(self):
        if self.flat_list:
            self.cursor_pos = 0
            self._ensure_cursor_visible()

    def _goto_last_object(self):
        """Загружаем все объекты и переходим к последнему."""
        global_idx = 0
        for file_idx, yaml_file in enumerate(self.yaml_files):
            for obj_idx in range(len(yaml_file)):
                self._load_object(file_idx, obj_idx, global_idx)
                global_idx += 1

        self._rebuild_flat_list()
        if self.flat_list:
            self.cursor_pos = len(self.flat_list) - 1
            self._ensure_cursor_visible()

    def _next_object(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]
        path = node.get_path()

        while node.parent != self.root and node.parent is not None:
            node = node.parent

        if node.global_idx is None:
            return

        next_global_idx = node.global_idx + 1

        if next_global_idx >= self.total_objects:
            self.status_message = "Это последний объект"
            return

        current = 0
        next_file_idx = 0
        next_obj_idx = 0

        for file_idx, yaml_file in enumerate(self.yaml_files):
            if current + len(yaml_file) > next_global_idx:
                next_file_idx = file_idx
                next_obj_idx = next_global_idx - current
                break
            current += len(yaml_file)

        key = (next_file_idx, next_obj_idx)
        if key not in self.loaded_objects:
            self._load_object(next_file_idx, next_obj_idx, next_global_idx)
            self._rebuild_flat_list()

        next_node = None
        for child in self.root.children:
            if child.global_idx == next_global_idx:
                next_node = child
                break

        if next_node:
            target = next_node.find_by_path(path[1:]) if len(path) > 1 else next_node
            if target is None:
                target = next_node

            self._rebuild_flat_list()
            for i, (n, _, _) in enumerate(self.flat_list):
                if n == target:
                    self.cursor_pos = i
                    self._ensure_cursor_visible()
                    break

    def _prev_object(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]
        path = node.get_path()

        while node.parent != self.root and node.parent is not None:
            node = node.parent

        if node.global_idx is None or node.global_idx == 0:
            self.status_message = "Это первый объект"
            return

        prev_global_idx = node.global_idx - 1

        current = 0
        prev_file_idx = 0
        prev_obj_idx = 0

        for file_idx, yaml_file in enumerate(self.yaml_files):
            if current + len(yaml_file) > prev_global_idx:
                prev_file_idx = file_idx
                prev_obj_idx = prev_global_idx - current
                break
            current += len(yaml_file)

        key = (prev_file_idx, prev_obj_idx)
        if key not in self.loaded_objects:
            self._load_object(prev_file_idx, prev_obj_idx, prev_global_idx)
            self._rebuild_flat_list()

        prev_node = None
        for child in self.root.children:
            if child.global_idx == prev_global_idx:
                prev_node = child
                break

        if prev_node:
            target = prev_node.find_by_path(path[1:]) if len(path) > 1 else prev_node
            if target is None:
                target = prev_node

            self._rebuild_flat_list()
            for i, (n, _, _) in enumerate(self.flat_list):
                if n == target:
                    self.cursor_pos = i
                    self._ensure_cursor_visible()
                    break

    def _search_current_field(self):
        if not self.flat_list:
            return

        node, _, _ = self.flat_list[self.cursor_pos]
        field_name = node.key

        if not field_name:
            self.status_message = "Нельзя искать по элементам списка"
            return

        pattern_str = self._input_string(f"Поиск в '{field_name}' (regex): ")
        if not pattern_str:
            return

        pattern = safe_regex_compile(pattern_str)
        if pattern is None:
            self.status_message = "Regex не скомпилирован, используется простой поиск"

        self.search_results.clear()

        global_idx = 0
        for file_idx, yaml_file in enumerate(self.yaml_files):
            for obj_idx in range(len(yaml_file)):
                self._load_object(file_idx, obj_idx, global_idx)
                global_idx += 1

        self._rebuild_flat_list()

        for obj_node in self.root.children:
            self._search_in_node(obj_node, field_name, pattern, pattern_str)

        if self.search_results:
            self.search_result_idx = 0
            self._goto_search_result(0)
            self.status_message = f"Найдено: {len(self.search_results)} совпадений"
        else:
            self.status_message = "Совпадений не найдено"

    def _search_in_node(self, node: YamlNode, field_name: str, 
                       pattern: Optional[re.Pattern], pattern_str: str):
        if node.is_leaf and node.key == field_name:
            value_str = str(node.value) if node.value is not None else ""
            if safe_regex_search(pattern, value_str, pattern_str):
                self.search_results.append(node)

        if not node.is_leaf:
            if not node.expanded:
                node.expand()
            for child in node.children:
                self._search_in_node(child, field_name, pattern, pattern_str)

    def _global_search(self):
        pattern_str = self._input_string("Глобальный поиск (regex): ")
        if not pattern_str:
            return

        pattern = safe_regex_compile(pattern_str)
        if pattern is None:
            self.status_message = "Regex не скомпилирован, используется простой поиск"

        self.search_results.clear()
        matching_fields = set()

        global_idx = 0
        for file_idx, yaml_file in enumerate(self.yaml_files):
            for obj_idx in range(len(yaml_file)):
                self._load_object(file_idx, obj_idx, global_idx)
                global_idx += 1

        self._rebuild_flat_list()

        for obj_node in self.root.children:
            self._global_search_in_node(obj_node, pattern, pattern_str, matching_fields)

        if self.search_results:
            self.search_result_idx = 0
            self.filter_fields = matching_fields
            self._rebuild_flat_list()
            self._goto_search_result(0)
            self.status_message = f"Найдено: {len(self.search_results)} в {len(matching_fields)} полях"
        else:
            self.status_message = "Совпадений не найдено"

    def _global_search_in_node(self, node: YamlNode, pattern: Optional[re.Pattern],
                              pattern_str: str, matching_fields: Set[str]):
        if node.is_leaf and node.key:
            value_str = str(node.value) if node.value is not None else ""
            if safe_regex_search(pattern, value_str, pattern_str):
                self.search_results.append(node)
                matching_fields.add(node.key)

        if not node.is_leaf:
            if not node.expanded:
                node.expand()
            for child in node.children:
                self._global_search_in_node(child, pattern, pattern_str, matching_fields)

    def _goto_search_result(self, idx: int):
        if idx >= len(self.search_results):
            return

        target = self.search_results[idx]

        node = target
        while node.parent and node.parent != self.root:
            if not node.parent.expanded:
                node.parent.expand()
            node = node.parent

        self._rebuild_flat_list()

        for i, (n, _, _) in enumerate(self.flat_list):
            if n == target:
                self.cursor_pos = i
                self._ensure_cursor_visible()
                break

    def _filter_dialog(self):
        fields = set()
        for child in self.root.children:
            self._collect_leaf_fields(child, fields)

        if not fields:
            self.status_message = "Нет полей для фильтрации"
            return

        fields_list = sorted(fields)
        selected = set(fields_list) if self.filter_fields is None else self.filter_fields.copy()

        cursor = 0

        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()

            header = "Выбор полей (пробел:вкл/выкл, Enter:применить, Esc:отмена)"
            try:
                self.stdscr.addnstr(0, 0, header[:width - 1], width - 1, curses.color_pair(2) | curses.A_BOLD)
            except:
                pass

            view_height = height - 2
            for i in range(view_height):
                idx = i
                if idx >= len(fields_list):
                    break

                field = fields_list[idx]
                checkbox = "[x]" if field in selected else "[ ]"
                text = f"{checkbox} {field}"

                attr = curses.color_pair(1) if idx == cursor else 0
                try:
                    self.stdscr.addnstr(i + 1, 0, text[:width - 1], width - 1, attr)
                except:
                    pass

            self.stdscr.refresh()

            key = self.stdscr.getch()

            if key in (ord('q'), ord('Q'), 27):
                break
            elif key in (curses.KEY_ENTER, 10, 13):
                self.filter_fields = selected if selected != set(fields_list) else None
                self._rebuild_flat_list()
                self.status_message = f"Фильтр: {len(selected)} полей" if selected else "Фильтр снят"
                break
            elif key in (curses.KEY_UP, ord('k')):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_DOWN, ord('j')):
                cursor = min(len(fields_list) - 1, cursor + 1)
            elif key == ord(' '):
                field = fields_list[cursor]
                if field in selected:
                    selected.remove(field)
                else:
                    selected.add(field)

    def _collect_leaf_fields(self, node: YamlNode, fields: Set[str]):
        if node.is_leaf:
            if node.record_idx is None and node.key:
                fields.add(node.key)
        else:
            if not node.expanded:
                node.expand()
            for child in node.children:
                self._collect_leaf_fields(child, fields)

    def _input_string(self, prompt: str) -> str:
        height, width = self.stdscr.getmaxyx()

        win_height = 3
        win_width = min(60, width - 4)
        win_y = (height - win_height) // 2
        win_x = (width - win_width) // 2

        win = curses.newwin(win_height, win_width, win_y, win_x)
        win.box()
        win.addnstr(1, 1, prompt[:win_width - 2], win_width - 2)
        win.refresh()

        curses.curs_set(1)
        curses.echo()

        input_str = ""
        try:
            input_bytes = win.getstr(1, len(prompt) + 1, win_width - len(prompt) - 3)
            input_str = input_bytes.decode('utf-8', errors='replace')

        except KeyboardInterrupt:
            pass

        except curses.error as e:
            log_error("Curses input error", e)
            self.status_message = "Ошибка ввода. Попробуйте изменить размер окна."

        except UnicodeDecodeError as e:
            log_error("Unicode decode error in input", e)
            self.status_message = "Ошибка кодировки. Используйте UTF-8."

        except Exception as e:
            log_error("Unexpected input error", e)
            self.status_message = f"Ошибка: {type(e).__name__}. Лог: {LOG_FILE}"

        finally:
            curses.noecho()
            curses.curs_set(0)

        return input_str.strip()


# =============================================================================
# Главная функция
# =============================================================================
def main(stdscr, filepaths: List[Path]):
    try:
        yaml_files = []
        for path in filepaths:
            yaml_file = YamlFile(path)
            yaml_files.append(yaml_file)

        viewer = YamlTuiViewer(stdscr, yaml_files)
        viewer.run()

    except SecurityError as e:
        stdscr.clear()
        try:
            stdscr.addstr(0, 0, f"Ошибка безопасности: {str(e)}")
            stdscr.addstr(2, 0, "Нажмите любую клавишу для выхода...")
        except:
            pass
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        import traceback
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        try:
            stdscr.addstr(0, 0, f"Ошибка: {str(e)}")
            tb = traceback.format_exc()
            for i, line in enumerate(tb.split('\n')[:height-3]):
                stdscr.addstr(i + 1, 0, line[:width-1])
            stdscr.addstr(height - 1, 0, "Нажмите любую клавишу для выхода...")
        except:
            pass
        stdscr.refresh()
        stdscr.getch()


if __name__ == "__main__":
    print(f"Консольная TUI-утилита для просмотра больших YAML файлов. Version {__version__}")

    if len(sys.argv) < 2:
        print("Использование: python yaml-viewer.py file1.yaml [file2.yaml ...]")
        sys.exit(1)

    try:
        filepaths = []
        for arg in sys.argv[1:]:
            path = validate_file_path(arg)
            filepaths.append(path)

        curses.wrapper(main, filepaths)

    except SecurityError as e:
        print(f"Ошибка безопасности: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)
