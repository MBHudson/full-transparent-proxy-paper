# full-transparent-proxy-paper

https://powerdns.org/tproxydoc/tproxy.md.html

Linux transparent proxy support
Introduction · High level · The routing part · Intercepting packets: the userspace part · The two roles of IP_TRANSPARENT · Getting the original destination address · Caveats · The -m socket line you find everywhere
DRAFT!

Introduction
The Linux kernel contains facilities for performing transparent proxying. In short this means that the operating system functions as a router, but some (or all) traffic gets redirected for userspace processing.

This could be used for example to implement a transparent http proxy which could then for example apply policy, scan for viruses etc. There are DNS applications too.

While the kernel does contain a file that describes this functionality, and this file is actually not wrong, it certainly is confusing. Other components required to really make transparent proxying work are described on various Stack Exchange pages. Other flags hang out in a number of manpages.

This document attempts to describe everything in one place, with references to the authoritative sources. Note that this documentation is quite at odds with other explanations found online, but it is believed this page is correct.

Some of the “pseudocode” examples actually compile when used with SimpleSockets. This is used because these examples are easier to read than the somewhat cumbersome raw BSD sockets API equivalent.

High level
Four components are involved:

A routing table that declares all IP addresses as local
iptables rules marking certain packets for processing by this routing table
And optionally map the traffic to a specific local address
A socket option IP_TRANSPARENT that marks sockets a suitable for receiving such traffic
Potentially: ebtables to perform these function in bridging mode
The routing part
When a packet enters a Linux system it is routed, dropped, or if the destination address matches a local address, accepted for processing by the system itself.

Local addresses can be specific, like 192.0.2.1, but can also match whole ranges. This is for example how all of 127.0.0.0/8 is considered as 'local'.

It is entirely possible to tell Linux 0.0.0.0/0 ('everything') is local, but this would leave it unable to connect to any remote address.

However, with a separate routing table, we can enable this selectively:

iptables -t mangle -I PREROUTING -p udp --dport 5301 -j MARK --set-mark 1
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
This says: mark all UDP packets coming in to the system to port 5301 with '1'. The next line sends those marked packets to routing table 100. And finally, the last line declares all of IPv4 as local in routing table 100.

Intercepting packets: the userspace part
With the routing rule and table above, the following simple code intercepts all packets routed through the system destined for 5301, regardless of destination IP address:

  Socket s(AF_INET, SOCK_DGRAM, 0);
  ComboAddress local("0.0.0.0", 5301);
  ComboAddress remote(local);

  SBind(s, local);

  for(;;) {
    string packet=SRecvfrom(s, 1500, remote);
    cout<<"Received a packet from "<<remote.toStringWithPort()<<endl;
  }
The two roles of IP_TRANSPARENT
The IP_TRANSPARENT socket option enables:

Binding to addresses that are not (usually) considered local
Receiving connections and packets from iptables TPROXY redirected sessions
Binding to non-local IP addresses
Regular sockets are used for transparent proxying, but a special flag, IP_TRANSPARENT, is set to indicate that this socket might receive data destined for a non-local addresses.

Note: as explained above, we can declare 0.0.0.0/0 as “local” (or ::/0), but if this is not in a default routing table, we still need this flag to convince the kernel we know what we are doing when we bind to a non-local IP address.

The following code spoofs a UDP address from 1.2.3.4 to 198.41.0.4:

  Socket s(AF_INET, SOCK_DGRAM, 0);
  SSetsockopt(s, IPPROTO_IP, IP_TRANSPARENT, 1);
  ComboAddress local("1.2.3.4", 5300);
  ComboAddress remote("198.41.0.4", 53);
  
  SBind(s, local);
  SSendto(s, "hi!", remote);
Note: this requires root or CAP_NET_ADMIN to work.

With tcpdump we can observe that an actual packet leaves the host:

tcpdump -n host 1.2.3.4
21:29:41.005856 IP 1.2.3.4.5300 > 198.41.0.4.53: [|domain]
IP_TRANSPARENT is mentioned in ip(7).

The iptables part
In the code examples above, traffic had to be delivered to a socket bound to the exact port of the intercepted traffic. We also had to bind the socket to 0.0.0.0 (or ::) for it to see all traffic.

iptables has a target called TPROXY which gives us additional flexibility to send intercepted traffic to a specific local IP address and simultaneously mark it too.

The basic syntax is:

iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10025 --on-ip 127.0.0.1
This says: take everything destined for a port 25 on TCP and deliver this for a process listening on 127.0.0.1:10025 and mark the packet with 1.

This mark then makes sure the packet ends up in the right routing table.

With the iptables line above, we can now bind to 127.0.0.1:10025 and receive all traffic destined for port 25. Note that the IP_TRANSPARENT option still needs to be set for this to work, even when we bind to 127.0.0.1.

Getting the original destination address
For TCP sockets, the original destination address and port of a socket is available via getsockname(). This is needed for example to setup a connection to the originally intended destination.

An example piece of code:

  Socket s(AF_INET, SOCK_STREAM, 0);
  SSetsockopt(s, IPPROTO_IP, IP_TRANSPARENT, 1);
  ComboAddress local("127.0.0.1", 10025);

  SBind(s, local);
  SListen(s, 128);

  ComboAddress remote(local), orig(local);
  int client = SAccept(s, remote);
  cout<<"Got connection from "<<remote.toStringWithPort()<<endl;

  SGetsockname(client, orig);
  cout<<"Original destination: "<<orig.toStringWithPort()<<endl;
For UDP, the IP_RECVORIGDSTADDR socket option can be set with setsockopt(). To actually get to that address, recvmsg() must be used which will then pass the original destination as a cmsg with index IP_ORIGDSTADDR containing a struct sockaddr_in.

Note: as of May 2017, many recently deployed Linux kernels have a bug which breaks IP_RECVORIGDSTADDR.

Caveats
None of this works locally. Packets need to actually enter your system and be routed.

First, make sure that the Linux machine is actually setup to forward packets:

sysctl net.ipv4.conf.all.forwarding=1
sysctl net.ipv6.conf.all.forwarding=1
Secondly, in many cases the reverse path filter may decide to drop your intercepted packets. The rp_filter can't be disabled globally, so for each interface do:

sysctl net.ipv4.conf.eth0.rp_filter=0
For reasons, the net.ipv4.conf.all.rp_filter actually can only be used to enable the rp_filter globally, not disable it.

The -m socket line you find everywhere
Many TPROXY iptables examples on the internet contain an unexplained refinement that uses -m socket -p tcp. The socket module of iptables matches patches that correspond to a local socket, which may be more precise or faster than navigating a set of specific rules.

The setup you'll find everywhere sets up a redirect chain which marks and accepts packets:

iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
The following then makes sure that everything that corresponds to an established local socket gets sent there, followed by what should happen to new packets:

iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10025 --on-ip 127.0.0.1
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10080 --on-ip 127.0.0.1
formatted by Markdeep 1.14  ✒




---


Transparent proxy support
=========================

This feature adds Linux 2.2-like transparent proxy support to current kernels.
To use it, enable the socket match and the TPROXY target in your kernel config.
You will need policy routing too, so be sure to enable that as well.

From Linux 4.18 transparent proxy support is also available in nf_tables.

1. Making non-local sockets work
================================

The idea is that you identify packets with destination address matching a local
socket on your box, set the packet mark to a certain value:

# iptables -t mangle -N DIVERT
# iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
# iptables -t mangle -A DIVERT -j MARK --set-mark 1
# iptables -t mangle -A DIVERT -j ACCEPT

Alternatively you can do this in nft with the following commands:

# nft add table filter
# nft add chain filter divert "{ type filter hook prerouting priority -150; }"
# nft add rule filter divert meta l4proto tcp socket transparent 1 meta mark set 1 accept

And then match on that value using policy routing to have those packets
delivered locally:

# ip rule add fwmark 1 lookup 100
# ip route add local 0.0.0.0/0 dev lo table 100

Because of certain restrictions in the IPv4 routing output code you'll have to
modify your application to allow it to send datagrams _from_ non-local IP
addresses. All you have to do is enable the (SOL_IP, IP_TRANSPARENT) socket
option before calling bind:

fd = socket(AF_INET, SOCK_STREAM, 0);
/* - 8< -*/
int value = 1;
setsockopt(fd, SOL_IP, IP_TRANSPARENT, &value, sizeof(value));
/* - 8< -*/
name.sin_family = AF_INET;
name.sin_port = htons(0xCAFE);
name.sin_addr.s_addr = htonl(0xDEADBEEF);
bind(fd, &name, sizeof(name));

A trivial patch for netcat is available here:
http://people.netfilter.org/hidden/tproxy/netcat-ip_transparent-support.patch


2. Redirecting traffic
======================

Transparent proxying often involves "intercepting" traffic on a router. This is
usually done with the iptables REDIRECT target; however, there are serious
limitations of that method. One of the major issues is that it actually
modifies the packets to change the destination address -- which might not be
acceptable in certain situations. (Think of proxying UDP for example: you won't
be able to find out the original destination address. Even in case of TCP
getting the original destination address is racy.)

The 'TPROXY' target provides similar functionality without relying on NAT. Simply
add rules like this to the iptables ruleset above:

# iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 50080

Or the following rule to nft:

# nft add rule filter divert tcp dport 80 tproxy to :50080 meta mark set 1 accept

Note that for this to work you'll have to modify the proxy to enable (SOL_IP,
IP_TRANSPARENT) for the listening socket.

As an example implementation, tcprdr is available here:
https://git.breakpoint.cc/cgit/fw/tcprdr.git/
This tool is written by Florian Westphal and it was used for testing during the
nf_tables implementation.

3. Iptables and nf_tables extensions
====================================

To use tproxy you'll need to have the following modules compiled for iptables:
 - NETFILTER_XT_MATCH_SOCKET
 - NETFILTER_XT_TARGET_TPROXY

Or the floowing modules for nf_tables:
 - NFT_SOCKET
 - NFT_TPROXY

4. Application support
======================

4.1. Squid
----------

Squid 3.HEAD has support built-in. To use it, pass
'--enable-linux-netfilter' to configure and set the 'tproxy' option on
the HTTP listener you redirect traffic to with the TPROXY iptables
target.

For more information please consult the following page on the Squid
wiki: http://wiki.squid-cache.org/Features/Tproxy4





---

https://www.xmodulo.com/how-to-set-up-transparent-proxy-on-linux.html
