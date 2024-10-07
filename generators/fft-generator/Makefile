# Makefile for compiling fft.c on RISC-V Linux

# Compiler and flags
CC = riscv64-linux-gnu-gcc #gcc
CFLAGS = -Wall -O2

# Target executable name
TARGET = fft

# Default rule
all: $(TARGET)

# Rule to compile fft.c
$(TARGET): fft32.c
	$(CC) $(CFLAGS) -o $(TARGET) fft32.c

# Clean up generated files
clean:
	rm -f $(TARGET)
