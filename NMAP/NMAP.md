_______

## Index

- [[#Introduction]]
- [[#Host discovery]]
- [[#Host and Port Scanning]]
- [[#Service enumeration]]
- [[#Saving the results]]
- [[#Nmap Scripts]]
- [[#Firewall and IDS/IPS Evasion]]

_______


## Introduction

### Use Cases

The tool is one of the most used tools by network administrators and IT security specialists. It is used to:

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

### Nmap Architecture

Nmap offers many different types of scans that can be used to obtain various results about our targets. Basically, Nmap can be divided into the following scanning techniques:

- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

___

## Host Discovery

| **Scanning Options** | **Description**                                                  |
| -------------------- | ---------------------------------------------------------------- |
| `10.129.2.0/24`      | Target network range.                                            |
| `-sn`                | Disables port scanning.                                          |
| `-oA tnet`           | Stores the results in all formats starting with the name 'tnet'. |

This scanning method works only if the firewalls of the hosts allow it. Otherwise, we can use other scanning techniques to find out if the hosts are active or not. We will take a closer look at these techniques in "[[#Firewall and IDS Evasion]]".

You can also take a file with IP's as input to nmap:

```shell-session
D4rsel@htb[/htb]$ cat hosts.lst

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

If we use the same scanning technique on the predefined list, the command will look like this:

```shell-session
D4rsel@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst
```

________

## Host and Port Scanning

###  Cheat Sheet

|**Scanning Options**|**Description**|
|---|---|
|`10.129.2.28`|Scans the specified target.|
|`-Pn`|Disables ICMP Echo requests.|
|`-n`|Disables DNS resolution.|
|`--disable-arp-ping`|Disables ARP ping.|
|`--packet-trace`|Shows all packets sent and received.|
|`-p 445`|Scans only the specified port.|
|`--reason`|Displays the reason a port is in a particular state.|
|`-sV`|Performs a service scan.|

There are a total of 6 different states for a scanned port we can obtain:

| **State**          | **Description**                                                                                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `open`             | This indicates that the connection to the scanned port has been established. These connections can be **TCP connections**, **UDP datagrams** as well as **SCTP associations**.                          |
| `closed`           | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an `RST` flag. This scanning method can also be used to determine if our target is alive or not. |
| `filtered`         | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.                  |
| `unfiltered`       | This state of a port only occurs during the **TCP-ACK** scan and means that the port is accessible, but it cannot be determined whether it is open or closed.                                           |
| `open\|filtered`   | If we do not get a response for a specific port, `Nmap` will set it to that state. This indicates that a firewall or packet filter may protect the port.                                                |
| `closed\|filtered` | This state only occurs in the **IP ID idle** scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.                                           |

By default nmap *scans the top 1000 TCP ports.* 

### Filtered Ports

When a port is shown as filtered, it can have several reasons. In most cases, `firewalls` have certain rules set to handle specific connections. The packets can either be `dropped`, or `rejected`. When a packet gets dropped, `Nmap` receives no response from our target, and by default, the retry rate (`--max-retries`) is set to `10`. This means `Nmap` will resend the request to the target port to determine if the previous packet was accidentally mishandled or not.

### Discovering Open UDP Ports

Some system administrators sometimes forget to filter the UDP ports in addition to the TCP ones. Since `UDP` is a `stateless protocol` and does not require a three-way handshake like TCP. We do not receive any acknowledgment. Consequently, the timeout is much longer, making the whole `UDP scan` (`-sU`) much slower than the `TCP scan` (`-sS`).

Let's look at an example of what a UDP scan (`-sU`) can look like and what results it gives us.

### Version Scan

Another handy method for scanning ports is the `-sV` option which is used to get additional available information from the open ports. This method can identify versions, service names, and details about our target.

________

## Service enumeration

We can also increase the `verbosity level` (`-v` / `-vv`), which will show us the open ports directly when `Nmap` detects them.

*Banner grabbing:*                  **IMPORTANT:** It can give you info that nmap can't.

```shell-session
D4rsel@htb[/htb]$  nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)



┌─[us-academy-2]─[10.10.14.141]─[htb-ac-230701@htb-34l8ebpkr7]─[~]
└──╼ [★]$ nc -nv 10.129.2.49 31337
(UNKNOWN) [10.129.2.49] 31337 (?) open
220 HTB{pr0F7pDv3r510nb4nn3r}
```

__________

## Saving the results

While we run various scans, we should always save the results. We can use these later to examine the differences between the different scanning methods we have used. `Nmap` can save the results in 3 different formats.

- Normal output (`-oN`) with the `.nmap` file extension
- Grepable output (`-oG`) with the `.gnmap` file extension
- XML output (`-oX`) with the `.xml` file extension

We can also specify the option (`-oA`) to save the results in all formats.

### Style sheets

With the XML output, we can easily create HTML reports that are easy to read, even for non-technical people. This is later very useful for documentation, as it presents our results in a detailed and clear way. To convert the stored results from XML format to HTML, we can use the tool `xsltproc`.

  Saving the Results

```shell-session
D4rsel@htb[/htb]$ xsltproc target.xml -o target.html
```

If we now open the HTML file in our browser, we see a clear and structured presentation of our results.

#### Nmap Report

![image](https://academy.hackthebox.com/storage/modules/19/nmap-report.png)

________

## Nmap Scripts

Nmap Scripting Engine (`NSE`) is another handy feature of `Nmap`. It provides us with the possibility to create scripts in Lua for interaction with certain services. There are a total of 14 categories into which these scripts can be divided:

| **Category** | **Description**                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`       | Determination of authentication credentials.                                                                                            |
| `broadcast`  | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute`      | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| `default`    | Default scripts executed by using the `-sC` option.                                                                                     |
| `discovery`  | Evaluation of accessible services.                                                                                                      |
| `dos`        | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| `exploit`    | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| `external`   | Scripts that use external services for further processing.                                                                              |
| `fuzzer`     | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| `intrusive`  | Intrusive scripts that could negatively affect the target system.                                                                       |
| `malware`    | Checks if some malware infects the target system.                                                                                       |
| `safe`       | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| `version`    | Extension for service detection.                                                                                                        |
| `vuln`       | Identification of specific vulnerabilities.                                                                                             |

We have several ways to define the desired scripts in `Nmap`.

#### Default Scripts

  Nmap Scripting Engine

```shell-session
D4rsel@htb[/htb]$ sudo nmap <target> -sC
```

#### Specific Scripts Category

  Nmap Scripting Engine

```shell-session
D4rsel@htb[/htb]$ sudo nmap <target> --script <category>
```

#### Defined Scripts

  Nmap Scripting Engine

```shell-session
D4rsel@htb[/htb]$ sudo nmap <target> --script <script-name>,<script-name>,...
```

__________

## Firewall and IDS/IPS Evasion

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`sT`) because they only send a TCP packet with only the `ACK` flag. When a port is closed or open, the host must respond with an `RST` flag. Unlike outgoing connections, all connection attempts (with the `SYN` flag) from external networks are usually blocked by firewalls. However, the packets with the `ACK` flag are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

### Decoys

There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (`-D`) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: `5`) of IP addresses separated by a colon (`:`). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. **Another critical point is that the decoys must be alive.** Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms.

```shell-session
D4rsel@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

Another scenario would be that ``only individual subnets would not have access to the server's specific services``. So we can also manually specify the source IP address (`-S`) to test if we get better results with this one. Decoys can be used for SYN, ACK, ICMP scans, and OS detection scans. So let us look at such an example and determine which operating system it is most likely to be.

```shell-session
D4rsel@htb[/htb]$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200
```

### DNS Proxying

By default, `Nmap` performs a reverse DNS resolution unless otherwise specified to find more important information about our target. These DNS queries are also passed in most cases because the given web server is supposed to be found and visited. The DNS queries are made over the `UDP port 53`. The `TCP port 53` was previously only used for the so-called "`Zone transfers`" between the DNS servers or data transfer larger than 512 bytes. More and more, this is changing due to IPv6 and DNSSEC expansions. These changes cause many DNS requests to be made via TCP port 53.

However, `Nmap` still gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`). This method could be fundamental to us if we are in a demilitarized zone (`DMZ`). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use `TCP port 53` as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.

Now that we have found out that the firewall accepts `TCP port 53`, it is very likely that IDS/IPS filters might also be configured much weaker than others. We can test this by trying to connect to this port by using `Netcat`.

#### Connect To The Filtered Port

```shell-session
D4rsel@htb[/htb]$ ncat -nv --source-port 53 10.129.2.28 50000

Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```

________

##   Cheat Sheet

The cheat sheet is a useful command reference for this module.

### Scanning Options

|**Nmap Option**|**Description**|
|---|---|
|`10.10.10.0/24`|Target network range.|
|`-sn`|Disables port scanning.|
|`-Pn`|Disables ICMP Echo Requests|
|`-n`|Disables DNS Resolution.|
|`-PE`|Performs the ping scan by using ICMP Echo Requests against the target.|
|`--packet-trace`|Shows all packets sent and received.|
|`--reason`|Displays the reason for a specific result.|
|`--disable-arp-ping`|Disables ARP Ping Requests.|
|`--top-ports=<num>`|Scans the specified top ports that have been defined as most frequent.|
|`-p-`|Scan all ports.|
|`-p22-110`|Scan all ports between 22 and 110.|
|`-p22,25`|Scans only the specified ports 22 and 25.|
|`-F`|Scans top 100 ports.|
|`-sS`|Performs an TCP SYN-Scan.|
|`-sA`|Performs an TCP ACK-Scan.|
|`-sU`|Performs an UDP Scan.|
|`-sV`|Scans the discovered services for their versions.|
|`-sC`|Perform a Script Scan with scripts that are categorized as "default".|
|`--script <script>`|Performs a Script Scan by using the specified scripts.|
|`-O`|Performs an OS Detection Scan to determine the OS of the target.|
|`-A`|Performs OS Detection, Service Detection, and traceroute scans.|
|`-D RND:5`|Sets the number of random Decoys that will be used to scan the target.|
|`-e`|Specifies the network interface that is used for the scan.|
|`-S 10.10.10.200`|Specifies the source IP address for the scan.|
|`-g`|Specifies the source port for the scan.|
|`--dns-server <ns>`|DNS resolution is performed by using a specified name server.|

### Output Options

|**Nmap Option**|**Description**|
|---|---|
|`-oA filename`|Stores the results in all available formats starting with the name of "filename".|
|`-oN filename`|Stores the results in normal format with the name "filename".|
|`-oG filename`|Stores the results in "grepable" format with the name of "filename".|
|`-oX filename`|Stores the results in XML format with the name of "filename".|

### Performance Options

|**Nmap Option**|**Description**|
|---|---|
|`--max-retries <num>`|Sets the number of retries for scans of specific ports.|
|`--stats-every=5s`|Displays scan's status every 5 seconds.|
|`-v/-vv`|Displays verbose output during the scan.|
|`--initial-rtt-timeout 50ms`|Sets the specified time value as initial RTT timeout.|
|`--max-rtt-timeout 100ms`|Sets the specified time value as maximum RTT timeout.|
|`--min-rate 300`|Sets the number of packets that will be sent simultaneously.|
|`-T <0-5>`|Specifies the specific timing template.|

