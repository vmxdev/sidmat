# sidmat
Simple DNS matcher

`sidmat` scans DNS traffic. If domain name in DNS server response matches given regex, resolved address (from A record) printed to stdout.

It can be useful for "domain filtering" or other operations when you need to use domain names instead of IP-addresses.

`sidmat` holds resolved addresses in memory, so each unique address printed only once.

It can use pcap or nflog (under Linux) for packet capture.


###Compiling
with pcap as data source:

```sh
$ cc -Wall sidmat.c -o sidmat -lpcap
```

nflog:
```sh
$ cc -Wall sidmat_nflog.c -o sidmat -lnetfilter_log
```

###Running
for pcap flavour first argument is interface name.

print all succesfully resolved addresses (with d option print domain names to stderr):
```sh
# ./sidmat eth0 "." d
 # youtube.com
 173.194.122.238
 # dropbox.com
 108.160.166.62
 ...
```

for nflog first add corresponding iptables rule.
scan all UDP traffic from port 53 (we need only DNS responses).
100 is nflog group number
```sh
# iptables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 100
```

first argument is nflog group
```sh
# ./sidmat 100 "." d
 # facebook.com
 69.171.230.5
 # twitter.com
 199.16.156.6
 # twitter.com
 199.16.156.102
 # twitter.com
 199.16.156.38
 ...
```

print resolved google.some.tld or sub.domain.google.some.tld
```sh
# ./sidmat eth0 "^google\.|\.google\."
```

###Using with iptables
block all traffic from site.com and subdomains
```sh
/opt/sidmat eth0 "^site\.com$|\.site\.com$" | /usr/bin/xargs -I {} /sbin/iptables -A INPUT -s {} -j DROP
```

###Using with ipset
create ip set 'site'
```sh
# /usr/sbin/ipset -N site iphash
```

fill 'site' set with ip addresses of site.com or sub.domain.site.com
```sh
/opt/sidmat eth0 "^site\.com$|\.site\.com$" | /usr/bin/xargs -I {} /usr/sbin/ipset -A site {}
```


In case of big domains list you can hold it in file. With 'f' option second argument interpreted as file name
```sh
# ./sidmat eth0 domains.txt df
```

File expected to be one-line regex ('domain1.tld$|domain2.tld$|domain3.tld$...')
