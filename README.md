lldb-capstone-arm
=================

## Install

1. Unzip and move `*.py` to **~/.lldb**
2. Load script in lldb like: `command script import ~/.lldb/dis_capstone.py`

or add `command script import ~/.lldb/dis_capstone.py` to **~/.lldbinit** (create if not exists)

## Example

Disassemble arm/thumb with *dis_capstone*:

![Screenshot](https://raw.github.com/upbit/lldb-capstone-arm/master/screenshot.png)
