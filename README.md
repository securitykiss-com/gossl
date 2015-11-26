# gossl

##Sign client certificates - openssl missing options


    gossl --csr client.csr --cakey ca.key --cacrt ca.crt --out client.crt --from "Jan 2 15:04:05 2006" --period 365d


You can inspect the generated certificate in human readable form with this command:


    openssl x509 -text -noout -in client.crt
