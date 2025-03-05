basedir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
srcdir := $(basedir)/src
vpath %.c $(srcdir) $(srcdir)/sha3-64 $(srcdir)/sha3

PROGRAMS ?= sha3-sw sha3-rocc sha3-rocc-test slh-dsa-rocc slh-dsa-sw  slh-dsa-rocc-64 slh-dsa-rocc-zeropadding
CC := $(TARGET)-gcc
OBJDUMP := $(TARGET)-objdump

CFLAGS += -I $(srcdir) 

hdrs := $(wildcard *.h) $(wildcard $(srcdir)/*.h)
objs ?=
ldscript ?=

%.o: $(srcdir)/%.c $(hdrs)
	$(CC) $(CFLAGS) -o $@ -c $<
%.o: %.c $(hdrs)
	$(CC) $(CFLAGS) -o $@ -c $<
%.o: %.S $(hdrs)
	$(CC) $(CFLAGS) -D__ASSEMBLY__=1 -o $@ -c $<

%.riscv: %.o $(objs) $(ldscript)
	$(CC) $(LDFLAGS) $(if $(ldscript),-T $(ldscript)) -o $@ $< $(objs)

%.dump: %.riscv
	$(OBJDUMP) -d $< > $@

.DEFAULT: elf

.PHONY: elf dumps
elf: $(addsuffix .riscv,$(PROGRAMS))
dumps: $(addsuffix .dump,$(PROGRAMS))

.PHONY: clean
clean:
	rm -f -- *.riscv *.o *.dump

.SUFFIXES:
.SUFFIXES: .o .c .S
