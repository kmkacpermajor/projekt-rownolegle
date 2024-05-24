# CUDA Compiler
NVCC := nvcc

# Compiler Flags
NVCCFLAGS := -lcudart -g -G

# Source files
SOURCES := crack_passwords.cu

# Output file
OUTPUT := crack_passwords.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	$(NVCC) -ccbin g++ $(NVCCFLAGS) -o $@ $^

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
