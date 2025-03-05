# command for spike:
```
source chipyard/env.sh
riscv64-unknown-elf-gcc sha3-sw.c -o sha3-sw
spike --extension=sha3 pk sha3-sw
```
# shake256.py
* install useful package
```
pip install pycryptodome
```
* run the code
```
python3 shake256.py

--------------------
output will like:
--------------------
SHAKE256 output (decimal):
[211, 249, 118, 142, 221, 94, 103, 158, 208, 75, 72, 129, 47, 14, 178, 138, 81, 90, 200, 235, 53, 184, 224, 102, 220, 73, 195, 12, 103, 154, 23, 15, 106, 140, 70, 104, 178, 200, 101, 100, 47, 23, 84, 74, 15, 61, 148, 184, 52, 26, 50, 122, 81, 243, 138, 208, 90, 91, 25, 126, 141, 27, 188, 52]
```
# added new folder in common.mk
```
basedir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
srcdir := $(basedir)/src
vpath %.c $(srcdir) $(srcdir)/sha3-64 $(srcdir)/sha3

PROGRAMS ?= sha3-sw sha3-rocc sha3-rocc-test slh-dsa-rocc slh-dsa-sw  slh-dsa-rocc-64 slh-dsa-rocc-zeropadding
```