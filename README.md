# FastRC4 - LibARC4

> **This RC4 implementation is not secure, it is a POC for an optimized RC4 implementation in ASM. You should never use this implementation for TLS, WEP, ... or other old protocols using RC4. You should never use it to encrypt secrets or very large file.**

## Description

This repository implements RC4 encryption with IV, written in ASM with few optimizations.

## Requirements

 - To use the shared library you don't need any requirements.
 - To use the python interface you need Python3 and the standard library.

## Compilation

```bash
nasm -felf64 ARC4.asm
ld -shared ARC4.o -o librc4.so
strip librc4.so
```

## Usages

### Exported functions

```c
char *get_iv();
void *encrypt(char *key, char *data, unsigned long long length);
void *decrypt(char *key, char iv[256], char *data, unsigned long long length);
void *generate_iv();
void *xor_key_iv();
void *generate_key(char *key);
void *arc4_null_byte(char *data);
void *arc4(char *data, unsigned long long length);
void *reset_key();
void *set_iv(char *iv);
```

```
arc4_null_byte([IN/OUT] char *data) -> NULL
arc4([IN/OUT] char *data, [IN] unsigned long long length) -> NULL
generate_iv() -> NULL
xor_key_iv() -> NULL
generate_key(char *key) -> NULL
reset_key() -> NULL
get_iv() -> char[256] // null byte terminate string
set_iv([IN] char iv[256]) -> NULL
encrypt([IN] char *key, [IN/OUT] char *data, [IN] unsigned long long length) -> NULL  // if length is 0 call arc4_null_byte
decrypt([IN] char *key, [IN] char iv[256], [IN/OUT] char *data, [IN] unsigned long long length) -> NULL // there is no way to decrypt string terminating by null byte because encrypted data can contains null byte
```

### Python interface

```python
from librc4 import RC4

rc4 = RC4(b'my key')
cipher = rc4.encrypt(b'my data')
secret = rc4.decrypt(cipher)
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).