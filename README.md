
# ipcrypt: IP-format-preserving encryption: 

Encrypts an IPv4 address to another IPv4 address 

Can be used to "anonymize" logs, etc.

Takes as argument a CSV file and the index of a field containing IP
addresses

Uses a custom 4-byte-block cipher, inspired from SipHash.

Set the variable `KEY` to a 16-byte secret key

Example use, with the default key `some 16-byte key`:
```
$ cat test.csv 
a,127.0.0.1
b,8.8.8.8
c,1.2.3.4
$ python ipcrypt.py test.csv 1 e
a,114.62.227.59
b,46.48.51.50
c,171.238.15.199
$ python ipcrypt.py test.csv 1 e > tmp
$ python ipcrypt.py tmp 1 d
a,127.0.0.1
b,8.8.8.8
c,1.2.3.4
```

The Go version has a similar syntax; for example
```
$ go build ipcrypt.go
$ ./ipcrypt test.csv 1 e
a,114.62.227.59
b,46.48.51.50
c,171.238.15.199
```

Copyright (c) 2015 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
Under CC0 license <http://creativecommons.org/publicdomain/zero/1.0/>
