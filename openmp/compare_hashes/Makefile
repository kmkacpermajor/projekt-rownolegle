# Compiler
CXX := g++

# Compiler Flags
CXXFLAGS := -fopenmp

# Source file
SOURCE := hash_dict.cpp

# Output file
OUTPUT := hash_dict.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
