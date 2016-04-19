# gossl

##Sign client certificates - openssl missing options

A simple, self-contained, no dependencies tool written in Go to sign client certificates overcoming some limitations of openssl.

    gossl --csr client.csr --cakey ca.key --cacrt ca.crt \
    --out client.crt --from "Jan 2 15:04:05 2006" --period 365d


It does roughly the same thing as this openssl command:

    openssl x509 -in client.csr -CAkey ca.key -CA ca.crt \
    -out client.crt -set_serial 01 -sha256 -req -days 365 

The differences are:
- does not depend on openssl, only Go standard library, compiled to standalone binary
- can specify certificate start date (openssl always takes current time)
- can specify certificate period in years, days, hours and minutes (in openssl shortest is 1 day)

You can inspect the generated certificate in human readable form with this command:

    openssl x509 -text -noout -in client.crt

Compile from [sources](https://github.com/securitykiss-com/gossl/releases) or grab the [binary](https://github.com/securitykiss-com/gossl/releases).

