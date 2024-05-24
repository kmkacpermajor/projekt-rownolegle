# CUDA Compiler
NVCC := nvcc

# Compiler Flags
NVCCFLAGS := -lcudart

# Source files
SOURCES := compare_hashes.cu

# Output file
OUTPUT := compare_hashes.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	$(NVCC) -o $@ $^ $(NVCCFLAGS)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
