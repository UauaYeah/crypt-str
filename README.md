## cryptstr

Simply **c++ 17** string encryption

## Quick Start

```c++
#include "cryptstr.hpp"

int main(void) {
  std::cout << crypt("Hello world!") << std::endl;
}
```

## Assembly output

Without cryptstr encryption
```asm
lea rdx, aCryptstr  ; "cryptstr"
mov rcx, cs:?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A ; std::basic_ostream<char,std::char_traits<char>> std::cout
```

With cryptstr
```asm
mov [rbp+100h+var_F8], 0B5h
mov [rbp+100h+var_F7], 0A4h
mov [rbp+100h+var_F6], 0AFh
mov [rbp+100h+var_F5], 0A6h
mov [rbp+100h+var_F4], 0A2h
mov [rbp+100h+var_F3], 0A5h
mov [rbp+100h+var_F2], 0A2h
mov [rbp+100h+var_F1], 0A4h
mov [rbp+100h+var_F0], 0
```
