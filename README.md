# YAML TUI Viewer

Terminal TUI viewer for large YAML files with tree navigation, lazy loading, filtering, search, and value inspection helpers.

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-red)](#security-features)
[![Version](https://img.shields.io/badge/Version-v1.1.0-brightgreen)](CHANGELOG.md)

<img width="1041" height="1185" alt="image" src="https://github.com/user-attachments/assets/fe4a6a09-5382-4bf7-83f5-a1cb4c61b77a" />

## Overview

**YAML Viewer** is a powerful terminal-based interactive viewer for large YAML files with a tree-like interface. It provides lazy loading, search, filtering capabilities, and protection against various DoS attacks.

## Features

- Interactive YAML tree viewer for terminal environments
- Lazy loading for large files and multi-document YAML
- Leaf value viewer with scrolling and wrap mode
- Base64 decode mode for values
- Pretty-printed JSON when decoded Base64 payload is JSON
- X.509 certificate inspection via `openssl x509 -noout -text -nameopt utf8`
- Field search, global search, and field filtering
- Support for English and Russian keyboard layouts for hotkeys
- Basic safety limits for large/hostile input:
  - Maximum depth limits
  - String length validation
  - Number digit limits
  - Array/object size constraints
  - Regex timeout protection
- Error logging to `yaml-viewer.log`

## Requirements

- Python 3.8+
- Unix/Linux/macOS terminal with `curses`
- Windows: `windows-curses` or WSL
- `openssl` in `PATH` for certificate inspection

## Usage

```bash
python yaml-viewer.py file1.yaml
python yaml-viewer.py file1.yaml file2.yaml
```


### Large Files

The viewer automatically handles large files with lazy loading. Only the first 20 objects are loaded initially, with more loaded as you navigate.
## Main Screen Keys

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit |
| `↑` / `↓` or `j` / `k` | Move cursor |
| `←` | Collapse current node |
| `→` or `l` | Expand current node |
| `Enter` | Open value or toggle node |
| `n` / `p` | Page down / page up |
| `Home` / `End` | Go to first / last object |
| `PgDn` / `PgUp` | Go to next / previous object |
| `w` | Toggle wrap mode |
| `a` / `z` | Expand / collapse current object |
| `x` / `v` | Expand / collapse all loaded objects |
| `g` | Go to object by number |
| `s` | Search in current field |
| `u` | Global search |
| `f` | Field filter dialog |

Notes:
- Letter hotkeys are case-insensitive.
- Letter hotkeys work in English and Russian keyboard layouts.

## Value Viewer Keys

| Key | Action |
|-----|--------|
| `q` / `Esc` | Close viewer |
| `↑` / `↓` | Vertical scroll |
| `←` / `→` | Horizontal scroll when wrap is off |
| `Home` / `End` | Jump to start / end |
| `PgUp` / `PgDn` | Scroll by page |
| `w` | Toggle wrap mode |
| `b` | Decode value as Base64 |
| `c` | Try to inspect value as X.509 certificate |
| `r` | Return to raw value |

Notes:
- If Base64 decoding fails, the error is shown in the header and the raw value remains visible.
- If certificate parsing fails, the error is shown in the header and the raw value remains visible.

## Security Limits

| Limit | Value |
|-------|-------|
| Maximum YAML depth | 100 |
| Maximum string length | 10 MB |
| Maximum number digits | 4300 |
| Maximum array items | 1,000,000 |
| Maximum object keys | 100,000 |
| Maximum file size | 10 GB |
| Regex timeout | 2 seconds |

## Changelog

See [CHANGELOG.md](CHANGELOG.md).### Additional Protections


### Additional Protections

- **Path Validation** - Prevents access to system files (`/dev/`, `/proc/`, `/sys/`)
- **Input Sanitization** - All user inputs are validated and sanitized
- **Timeout Handling** - Operations that take too long are automatically terminated
- **Error Isolation** - Parse errors in one document don't affect others

## Configuration

You can adjust the following constants in the source code:

```python
MAX_YAML_DEPTH = 100          # Maximum nesting depth
MAX_STRING_LENGTH = 10485760  # 10 MB
MAX_FILE_SIZE = 10737418240   # 10 GB
CACHE_SIZE = 200              # LRU cache size
PRELOAD_OBJECTS = 20          # Objects to load initially
LOAD_BATCH_SIZE = 5           # Objects to load when scrolling
```

## Log File

All errors and warnings are logged to `yaml-viewer.log` in the current directory. The log includes:
- Timestamp
- Error context
- Exception type and message
- Full traceback
### Searching for Specific Values

1. Navigate to a field
2. Press `s`
3. Enter regex pattern
4. Browse through matches

### Filtering Fields

1. Press `f`
2. Use arrow keys to navigate
3. Press `Space` to toggle fields
4. Press `Enter` to apply filter

## Troubleshooting

### "File too large" error

The file exceeds the 10GB limit. You can increase `MAX_FILE_SIZE` in the source code.

### "Regex timeout" warning

Complex regex patterns may timeout. Use simpler patterns or increase `REGEX_TIMEOUT`.

### Display issues

Ensure your terminal supports UTF-8 encoding and has sufficient dimensions.

### Windows compatibility

On Windows, install `windows-curses`:

```bash
pip install windows-curses
```

## License

MIT. See [LICENSE](LICENSE).
## Author

**Tarasov Dmitry**

- Email: dtarasov7@gmail.com

## Acknowledgments

- Built with Python's `curses` library
- Inspired by terminal-based file viewers
- Security features based on OWASP guidelines

---

**Note**: This tool is designed for viewing and navigating YAML files. It does not modify files in any way.

---

## Attribution
Parts of this code were generated with assistance 
