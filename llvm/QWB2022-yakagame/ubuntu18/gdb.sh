gdb \
    -ex "file opt-8" \
    -ex 'set args -load ./yaka.so -ayaka exp.ll' \
    -ex 'b *(0x4bb7e3)' \
    -ex 'r' \
    -ex 'si' \
    -ex 'b *(0xD19E+0x7ffff238d000)' \
    -ex 'c' \
    -ex 'c' \
    -ex 'x/16gx 0x2169A8+0x7ffff238d000' \
    -ex 'c' \
    -ex 'c' \
    -ex 'c' \
    -ex 'x/16gx 0x2169A8+0x7ffff238d000' \
