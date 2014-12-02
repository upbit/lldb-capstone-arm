lldb-capstone-arm
=================

## Setup

1. Unzip and move `*.py` to **~/.lldb**
2. Install [capstone](https://github.com/aquynh/capstone) core (MacOS: or move `macos/libcapstone.dylib` to `/usr/local/lib/`)
3. Install capstone Python bindings: `pip install capstone`
4. Load script in lldb like: `command script import ~/.lldb/dis_capstone.py`

or add `command script import ~/.lldb/dis_capstone.py` to **~/.lldbinit** (create if not exists)

## Example

Disassemble arm/thumb with *dis_capstone*:

![Screenshot](https://raw.github.com/upbit/lldb-capstone-arm/master/screenshot.png)
