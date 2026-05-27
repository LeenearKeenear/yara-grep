# yara-grep
YARA match viewer. Like `grep -C` but for binary YARA hits.

## How to build
```bash
make
```
or 
```bash
g++ -std=c++17 -O2 -Wall yara-grep.cpp $(pkg-config --libs yara) -o yara-grep
```

## Usage
```bash
./yara-grep rule.yar target.bin
./yara-grep rule.yar target.bin -C 32
```
