# Compiler
CXX := g++

# Compiler Flags
CXXFLAGS := -w

# Libraries
LIBS := -lssl -lcrypto

# Source file
SOURCE := hash_dict.cpp

# Output file
OUTPUT := hash_dict.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
