# YAML Viewer - TUI YAML File Viewer

## Overview

**YAML Viewer** is a powerful terminal-based interactive viewer for large YAML files with a tree-like interface. It provides lazy loading, search, filtering capabilities, and protection against various DoS attacks.

![YAML Viewer Demo](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

## Features

- 🌳 **Interactive Tree Interface** - Navigate YAML structures with ease
- ⚡ **Lazy Loading** - Efficient handling of large files (up to 10GB)
- 🔍 **Search Capabilities** - Both field-specific and global regex search
- 🎯 **Field Filtering** - Show only fields you're interested in
- 📜 **Multi-document Support** - Handle YAML files with multiple documents
- 🛡️ **Security Protection** - Built-in safeguards against DoS attacks:
  - Maximum depth limits
  - String length validation
  - Number digit limits
  - Array/object size constraints
  - Regex timeout protection
- 📦 **Caching System** - Optimized performance with LRU cache
- 📏 **Text Wrapping** - Toggle wrap mode for long values
- 📝 **Error Logging** - Comprehensive error tracking in `yaml-viewer.log`

## Requirements

- Python 3.6 or higher
- `curses` library (built-in on Unix/Linux/macOS, requires `windows-curses` on Windows)

## Installation

### Unix/Linux/macOS

```bash
# Clone the repository
git clone https://github.com/yourusername/yaml-viewer.git
cd yaml-viewer

# Install dependencies (if any)
pip install -r requirements.txt
```

### Windows

```bash
# Install windows-curses
pip install windows-curses

# Clone and run
git clone https://github.com/yourusername/yaml-viewer.git
cd yaml-viewer
```

## Usage

### Basic Usage

```bash
python yaml-viewer.py file1.yaml
```

### Multiple Files

```bash
python yaml-viewer.py file1.yaml file2.yaml file3.yaml
```

### Large Files

The viewer automatically handles large files with lazy loading. Only the first 20 objects are loaded initially, with more loaded as you navigate.

## Key Bindings

| Key | Action |
|-----|--------|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `←` / `h` | Collapse current node |
| `→` / `l` | Expand current node |
| `Enter` | Toggle expand/collapse |
| `n` | Page down |
| `p` | Page up |
| `w` | Toggle text wrapping |
| `s` | Search in current field |
| `F` | Global search (regex) |
| `f` | Field filter dialog |
| `a` | Expand current object |
| `z` | Collapse current object |
| `A` | Expand all loaded objects |
| `Z` | Collapse all objects |
| `g` | Go to object by number |
| `Home` | Go to first object |
| `End` | Go to last object |
| `PgDn` | Next object |
| `PgUp` | Previous object |
| `q` / `Esc` | Quit |

## Security Features

The viewer includes multiple layers of security protection:

### Resource Limits

| Limit | Value |
|-------|-------|
| Maximum YAML depth | 100 levels |
| Maximum string length | 10 MB |
| Maximum number digits | 4,300 |
| Maximum array items | 1,000,000 |
| Maximum object keys | 100,000 |
| Maximum file size | 10 GB |
| Regex timeout | 2 seconds |

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

## Screenshots

*(Add screenshots of the viewer in action here)*

## Examples

### Viewing a Single YAML File

```bash
python yaml-viewer.py config.yaml
```

### Comparing Multiple Configuration Files

```bash
python yaml-viewer.py dev.yaml staging.yaml prod.yaml
```

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

MIT License - see [LICENSE](LICENSE) file for details.

## Author

**Tarasov Dmitry**

- Email: dtarasov7@gmail.com.com

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Version History

### 1.0.0 (2026)

- Initial release
- Tree-based navigation
- Search and filtering
- Security protections
- Multi-document support

## Acknowledgments

- Built with Python's `curses` library
- Inspired by terminal-based file viewers
- Security features based on OWASP guidelines

---

**Note**: This tool is designed for viewing and navigating YAML files. It does not modify files in any way.

---

## Attribution
Parts of this code were generated with assistance 
