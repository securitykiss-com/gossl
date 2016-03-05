// Copyrite (c) 2015 SecurityKISS Ltd (http://www.securitykiss.com)  
//
// The MIT License (MIT)
//
// Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead.
// Fight intellectual "property".
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
    "flag"
    "fmt"
    "math/big"
    "os"
    "time"
    "regexp"
    "strconv"
)

func uuidBigInt() (*big.Int, error) {
    limit := new(big.Int).Lsh(big.NewInt(1), 128)
    return rand.Int(rand.Reader, limit)
}

func uuidString() (string, error) {
    bint, err := uuidBigInt()
    if err != nil {
        return "", err
    }
    b := bint.Bytes()
    return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}


func x509sign(cakey *rsa.PrivateKey, cacrt *x509.Certificate, csr *x509.CertificateRequest, notBefore *time.Time, notAfter *time.Time) ([]byte, error) {
    serialNumber, err := uuidBigInt()
    if err != nil {
        return nil, err
    }
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: csr.Subject,
        NotBefore: *notBefore,
        NotAfter:  *notAfter,
    }
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, cacrt, csr.PublicKey, cakey)
    if err != nil {
        return nil, err
    }
    return derBytes, nil
}

func x509signCmd(cakeyfie, cacrtfile, csrfile *string, notBefore, notAfter *time.Time, outfile *string) error {
    csr, err := parseCsr(csrfile)
    if err != nil {
        return err
    }
    cakey, err := parseCakey(cakeyfile)
    if err != nil {
        return err
    }
    cacrt, err := parseCacrt(cacrtfile)
    if err != nil {
        return err
    }
    derBytes, err := x509sign(cakey, cacrt, csr, notBefore, notAfter)
    if err != nil {
        return err
    }
    err = saveCrt(derBytes, outfile)
    if err != nil {
        return err
    }
    return nil
}

func parseCsr(csrfile *string) (*x509.CertificateRequest, error) {
    csrbytes, err := ioutil.ReadFile(*csrfile)
    if err != nil {
        return nil, err
    }
    csrblock, _ := pem.Decode(csrbytes)
    if csrblock == nil {
        return nil, fmt.Errorf("PEM encoded data not found in %s", *csrfile)
    }
    return x509.ParseCertificateRequest(csrblock.Bytes)
}

func parseCakey(cakeyfile *string) (*rsa.PrivateKey, error) {
    cakeybytes, err := ioutil.ReadFile(*cakeyfile)
    if err != nil {
        return nil, err
    }
    cakeyblock, _ := pem.Decode(cakeybytes)
    if cakeyblock == nil {
        return nil, fmt.Errorf("Not valid CA key %s", *cakeyfile)
    }
    der := cakeyblock.Bytes

    // Try to parse as PKCS1
    cakey1, err := x509.ParsePKCS1PrivateKey(der)
    if err == nil {
        return cakey1, err
    }

    // Otherwise try PKCS8
    cakey8, err := x509.ParsePKCS8PrivateKey(der)
    if err != nil {
        return nil, err
    }
    switch k := cakey8.(type) {
    case *rsa.PrivateKey:
        return k, nil
    default:
        return nil, fmt.Errorf("CA key %s not an PKCS8 RSA private key", cakeyfile)
    }

}

func parseCacrt(cacrtfile *string) (*x509.Certificate, error) {
    cacrtbytes, err := ioutil.ReadFile(*cacrtfile)
    if err != nil {
        return nil, err
    }
    cacrtblock, _ := pem.Decode(cacrtbytes)
    if (cacrtblock == nil) {
        return nil, fmt.Errorf("Not valid CA crt %s", *cacrtfile)
    }
    return x509.ParseCertificate(cacrtblock.Bytes)
}

func parseDates(validFrom, validFor *string) (*time.Time, *time.Time, error) {
    var notBefore, notAfter time.Time
    var err error
    if len(*validFrom) == 0 {
        notBefore = time.Now()
    } else {
        notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
        if err != nil {
            return nil, nil, fmt.Errorf("Could not parse 'from' date")
        }
    }
    m := regexp.MustCompile(`^(\d+)([ydhm])$`).FindStringSubmatch(*validFor)
    if m == nil {
        return nil, nil, fmt.Errorf("Could not parse 'period'")
    }
    n, err := strconv.Atoi(m[1])
    if err != nil {
        return nil, nil, fmt.Errorf("Could not parse 'period' unit")
    }
    switch m[2] {
    case "y":
        notAfter = notBefore.AddDate(n, 0, 0)
    case "d":
        notAfter = notBefore.AddDate(0, 0, n)
    case "h":
        notAfter = notBefore.Add(time.Hour * time.Duration(n))
    case "m":
        notAfter = notBefore.Add(time.Minute * time.Duration(n))
    }

    return &notBefore, &notAfter, nil
}


func saveCrt(derBytes []byte, filename *string) error {
    certOut, err := os.Create(*filename)
    defer certOut.Close()
    if err != nil {
        return err
    }
    return pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}


func usage(err error) {
    fmt.Println(err)
    flag.Usage()
    os.Exit(1)
}

func handleErr(err error) {
    if err != nil {
        usage(err)
    }
}

var (
    csrfile    = flag.String("csr", "", "Certificate Signing Request file")
    cakeyfile  = flag.String("cakey", "", "CA private key")
    cacrtfile  = flag.String("cacrt", "", "CA certificate")
    outfile    = flag.String("out", "", "Output certificate file")
    validFrom  = flag.String("from", "", "Creation date formatted as 'Jan 2 15:04:05 2006'. Default is current time")
    validFor   = flag.String("period", "", "Duration that certificate is valid for. E.g. 10y or 3650d or 24h or 30m (years, days, hours, minutes)")
)

func main() {
    var err error
    flag.Parse()

    if (*csrfile == "" || *cakeyfile == "" || *cacrtfile == "" || *outfile == "" || *validFor == "") {
        flag.Usage()
        os.Exit(1)
    }

    notBefore, notAfter, err := parseDates(validFrom, validFor)
    handleErr(err)

    err = x509signCmd(cakeyfile, cacrtfile, csrfile, notBefore, notAfter, outfile)
    handleErr(err)

}



