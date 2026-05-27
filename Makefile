CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = $(shell pkg-config --libs yara 2>/dev/null || echo -lyara)

yara-grep: yara-grep.cpp
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f yara-grep

.PHONY: clean
