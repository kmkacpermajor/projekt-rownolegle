# CUDA Compiler
NVCC := nvcc

# Compiler Flags
NVCCFLAGS := -lcudart

# Source files
SOURCES := hash_dict.cu md5.cu sha256.cu

# Output file
OUTPUT := hash_dict.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	$(NVCC) -o $@ $^ $(NVCCFLAGS)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
