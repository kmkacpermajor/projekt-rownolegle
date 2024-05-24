# Compiler
CXX := g++

# Compiler Flags
CXXFLAGS := -fopenmp

# Libraries
LIBS := -lssl -lcrypto

# Source file
SOURCE := crack_passwords.cpp

# Output file
OUTPUT := crack_passwords.o

# Makefile Targets
all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
