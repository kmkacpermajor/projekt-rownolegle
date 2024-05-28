# Compiler
CXX := g++

# Compiler Flags
CXXFLAGS := -w

# Source file
SOURCE := compare_hashes.cpp

# Output file
OUTPUT := compare_hashes.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
