# sidmat
Simple DNS matcher

`sidmat` scans DNS traffic. If domain name in DNS server response matches given regex, resolved address (from A record) printed to stdout.

It can be useful for "domain filtering" or other operations when you need to use domain names instead of IP-addresses.

`sidmat` can use pcap or nflog (under Linux) for packet capture.


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
For pcap flavour first argument is interface name. For nflog first argument is nflog group.

Second argument is regular expression and third is additional options.

Print all succesfully resolved addresses (with 'd' option print domain names to stderr):
```sh
# ./sidmat eth0 "." d
 # youtube.com
 173.194.122.238
 # dropbox.com
 108.160.166.62
 ...
```

For nflog first add corresponding iptables rule.
scan all UDP traffic from port 53 (we need only DNS responses).
100 is nflog group number
```sh
# iptables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 100
```

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

Print resolved google.some.tld or sub.domain.google.some.tld
```sh
# ./sidmat eth0 "^google\.|\.google\."
```

Print tab-separated time, address and domain for all succesfully resolved domains
```sh
# ./sidmat eth0 "." iu | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), "\t", $0; fflush(); }'
2015-12-01 22:18:03 	 213.180.204.3	www.ya.ru
2015-12-01 22:18:03 	 93.158.134.3	www.ya.ru
...
```

###Using with iptables

Be very carefull with blocking traffic. Utility does not check IP addresses in DNS response, so you can get unexpected results from it.

Block all traffic from site.com and subdomains
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

###Additional options

By default `sidmat` holds resolved addresses in memory, so each unique address printed only once.

This behavior can be changed with 'u' option.

In case of big domains list you can hold it in file. With 'f' option second argument interpreted as file name
```sh
# ./sidmat eth0 domains.txt df
```

File expected to be one-line regex
