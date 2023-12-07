gdb \
    -ex "file opt-12" \
    -ex 'set args -load ./mbaPass.so -mba exp.ll -S' \
    -ex 'b *(0x432702)' \
    -ex 'r' \
    -ex 'si' \
    -ex 'b *(0x7ffff7fb6000+0xEFCD)' \
    -ex 'c' \
    -ex 'x/12i 0x7ffff7ff7fde' \
    -ex 'x/2gx 0x7ffff7ff7feb' \
    -ex 'c' \
    -ex 'x/12i 0x7ffff7ff7fde' \


