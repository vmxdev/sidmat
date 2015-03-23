# sidmat
Simple DNS matcher

`sidmat` listens on specified interface for DNS responses

If domain name in response matched against given regex, resolved address (from A record) is printed to stdout

`sidmat` holds resolved addresses in memory, so each unique address printed only once

###Compiling:
(you must have libpcap development package installed)

```sh
$ cc -Wall sidmat.c -o sidmat -lpcap
```

###Testing:
(will print all succesfully resolved addresses)
```sh
# ./sidmat eth0 ""
```

(with 'd' option will print also mathed domain name to stderr)
```sh
# ./sidmat eth0 "." d
 # youtube.com
 173.194.122.238
 # dropbox.com
 108.160.166.62
 ...
```

(will print resolved google.some.tld or sub.domain.google.some.tld)
```sh
# ./sidmat eth0 "^google\.|\.google\."
```

###Using with ipset:
(create ip set 'site')
```sh
# /usr/sbin/ipset -N site iphash
```

(fill 'site' set with ip addresses of site.com or sub.domain.site.com)
```sh
# /usr/bin/stdbuf -oL /opt/sidmat eth0 "^site\.com$|\.site\.com$" | /usr/bin/xargs -I {} /usr/sbin/ipset -A site {}
