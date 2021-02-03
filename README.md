# TP-LINK-POC_2

TP-Link router have a stack overflow in tddpd server running via port 20002.

Any user can get remote code execution through LAN, this vulnerability currently affects the latest versions of WR\WDR series, which include WDR7400,WDR7500,WDR7660,WDR7800,WDR8400,WDR8500,WDR8600,WDR8620,WDR8640,WDR8660,WR880N,WR886N,WR890N,WR890N,WR882N,WR708N,WR842N,WR802N,WR710N,WR706N,WR702N etc. It affects the linux system and vxworks system. we believe there are much more models suffered from this vuln.

## Vulnerability description 

This vulnerability happen when tddpd server receive data by usinng recvfrom `udp port 20002`.Then with a series data processing,it arrive `memcopy`,we can contorl `a1` and `v5`that It lead to a stack buffer overflow to execute arbitrary code.

**It's different from CVE-2020-28877**

![](./poc.png)

## poc

Refer to this video: [poc_video](./poc.mkv)

## Timeline

2020.10.24 show in GeekPwn

2020.12.01 report to CVE and TP-Link

2020.12.12 TP-Link reply and fix it
