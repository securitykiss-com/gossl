// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package main

import (
    "crypto/ecdsa"
//    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
//    "crypto/x509/pkix"
    "encoding/pem"
    "io/ioutil"
    "flag"
    "fmt"
    "log"
    "math/big"
//    "net"
    "os"
//    "strings"
    "time"
)

var (
    host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
    validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
    validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
    isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
    rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
    ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521")
)

func main() {
    var err error
    flag.Parse()

    csrfile := "/home/sk/seckiss/vigo/gossl/client.csr"
    cakeyfile := "/home/sk/seckiss/confidential/sk/keys/fruho/vpn/ca.key"
    cacrtfile := "/home/sk/seckiss/confidential/sk/keys/fruho/vpn/ca.crt"


    csrbytes, err := ioutil.ReadFile(csrfile)
    if err != nil {
        panic(err)
    }
    csrblock, _ := pem.Decode(csrbytes)
    if csrblock == nil {
        panic("Not valid CSR")
    }
    asn := csrblock.Bytes
    certRequest, err := x509.ParseCertificateRequest(asn)
    fmt.Printf("CSR Subject=%v\n", certRequest.Subject)



    cakeybytes, err := ioutil.ReadFile(cakeyfile)
    if err != nil {
        panic(err)
    }
    cakeyblock, _ := pem.Decode(cakeybytes)
    if cakeyblock == nil {
        panic("Not valid CA key")
    }
    der := cakeyblock.Bytes

//    fmt.Printf("der=%v\n", der)
    cakey, err := x509.ParsePKCS8PrivateKey(der)
//    fmt.Printf("%T\n", cakey)
    switch cakey.(type) {
    case *rsa.PrivateKey:
//        cakeyrsa := cakey.(*rsa.PrivateKey)
        //cakeypublic := cakeyrsa.PublicKey

//        fmt.Printf("cakeyrsa=%s\n", cakeyrsa)
    default:
        panic("CA key not *rsa.PrivateKey")
    }


    cacrtbytes, err := ioutil.ReadFile(cacrtfile)
    if err != nil {
        panic(err)
    }
    cacrtblock, _ := pem.Decode(cacrtbytes)
    if (cacrtblock == nil) {
        panic("Not valid CA crt")
    }
    asn = cacrtblock.Bytes

    cacrt, err := x509.ParseCertificate(asn)
//    fmt.Printf("cacrt=%v\n", cacrt)




    var notBefore time.Time
    if len(*validFrom) == 0 {
        notBefore = time.Now()
    } else {
        notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
            os.Exit(1)
        }
    }

    notAfter := notBefore.Add(*validFor)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        log.Fatalf("failed to generate serial number: %s", err)
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: certRequest.Subject,
        NotBefore: notBefore,
        NotAfter:  notAfter,
    }


    derBytes, err := x509.CreateCertificate(rand.Reader, &template, cacrt, certRequest.PublicKey, cakey.(*rsa.PrivateKey))
    if err != nil {
        log.Fatalf("Failed to create certificate: %s", err)
    }

    certOut, err := os.Create("cert.pem")
    if err != nil {
        log.Fatalf("failed to open cert.pem for writing: %s", err)
    }
    pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    certOut.Close()
    log.Print("written cert.pem\n")

}



