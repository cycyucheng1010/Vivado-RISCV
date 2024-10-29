# command for spike:
```
source chipyard/env.sh
riscv64-unknown-elf-gcc sha3-sw.c -o sha3-sw
spike --extension=sha3 pk sha3-sw
```