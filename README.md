Check out pf.c and main.c

Contents of `common/` folder were copied from `github.com/jovanbulck/sgx-tutorial-space18/` unless stated otherwise

## Compiling
Make sure the submodule is initialized/updated

```
git submodule update --init mbedtls
git submodule update --init mbedtls/crypto
```

### CMake
First create separate `build` dir within `thesis_exp` folder, then invoke cmake and make from there:

```
mkdir build && cd build

cmake ..

make thesis_exp
```
Then execute the thesis_exp target:

`./thesis_exp`

## Notes

### Var size ideas:

- Keep static at 16, 64 or 4096 bytes
- Use malloc metadata `malloc_usable_size`--> PROBLEM: metadata currently gets encrypted as well.
SOL(?): carefully indicate non-metadata regions (still needs to be >16 bytes) or keep metadata in custom structure
    - Maybe not very realistic? malloc metadata not always present

### Current problems:

- Declaration of multiple vars within 16 byte region eg **int_a** @ 0x00 and **int_b** @ 0x08: 
**int_a** memory access will decr/encr 16 byte region starting from 0x00 and thus include **int_b**
    - Accessing **int_b** will attempt to decrypt [0x08, 0x18]
    - Writing to **int_b** will first overwrite [0x08, 0x10] then encrypt [0x08, 0x18], leaving [0x00, 0x10] corrupted.
        - Possible SOL: divide memory into static blocks and always encr/decr nearest previous to access --> 
        would need change in current implementation: writes would have to decrypt block first and encrypt again after.
        Also: still need to find var size somehow in case it extends 16 bytes --> needs multiple blocks decrypted
