lldb-capstone-arm
=================

A lldb script for disassemble ARM(Thumb)/ARM64 code by [Capstone Engine](https://github.com/aquynh/capstone)

## Setup

Install [capstone](https://github.com/aquynh/capstone) and Python bindings:

~~~sh
brew install capstone
sudo pip install capstone
~~~

Then deploy scripts:

1. Unzip and move `*.py` to **~/.lldb**
2. Load script in lldb like: `command script import ~/.lldb/dis_capstone.py`

or add `command script import ~/.lldb/dis_capstone.py` to **~/.lldbinit** (create if not exists)

## Example

Thumb code disassemble compare:

![Screenshot](https://raw.github.com/upbit/lldb-capstone-arm/master/screenshot.png)

*discs* with -f and -h:

~~~
(lldb) discs -f
  SBThread: tid = 0x357e9, frame #0: 0x31c366ba libobjc.A.dylib`objc_retain + 10
      Address: libobjc.A.dylib[0x2f2286ba] (libobjc.A.dylib.__TEXT.__text + 116410)
      Summary: libobjc.A.dylib`objc_retain + 10

-> 0x31c366ba:  09 7C            ldrb     r1, [r1, #0x10]
   0x31c366bc:  11 F0 02 0F      tst.w    r1, #2
   0x31c366c0:  18 BF            it       ne
   0x31c366c2:  00 F0 8F B9      b.w      #0x31c369e4
   0x31c366c6:  47 F6 0A 21      movw     r1, #0x7a0a
   0x31c366ca:  C0 F2 CF 21      movt     r1, #0x2cf
   0x31c366ce:  79 44            add      r1, pc
   0x31c366d0:  09 68            ldr      r1, [r1]
   0x31c366d2:  09 68            ldr      r1, [r1]
   0x31c366d4:  F2 F7 44 BC      b.w      #0x31c28f60
   0x31c366d8:  F0 B5            push     {r4, r5, r6, r7, lr}

(lldb) discs -h
Usage: discs (-f) (-s <addr>) (-l <len>) (-A <arm|arm64>) (-M <arm|thumb>)

Options:
   -h, --help            show this help message and exit
   -s START_ADDR, --start-addr=START_ADDR
                         start address (default: pc)
   -l LENGTH, --length=LENGTH
                         decode bytes length (default: 32)
   -A ARCH, --arch=ARCH  arch type: arm,arm64 (default: arm)
   -M MODE, --mode=MODE  mode type: arm,thumb (auto select by cpsr[b:5])
   -f, --full            show full outputs
~~~
