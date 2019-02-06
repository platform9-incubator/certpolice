package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type params struct {
	Params map[string]string
}

type vault struct {
	Url string `yaml:"url"`
	Token string `yaml:"token"`
}

type internal_cert struct {
	Name string `yaml:"name"`
	CAName string `yaml:"ca"`
	KeyPath string `yaml:"key"`
	CertPath string `yaml:"cert"`
	CombinedPath string `yaml:"combined"`
}

type external_cert struct {
	Name string `yaml:"name"`
	VaultName string `yaml:"vault"`
	SecretPath string `yaml:"secret-path"`
	KeyPath string `yaml:"key"`
	CertPath string `yaml:"cert"`
	CombinedPath string `yaml:"combined"`
}

type internal_ca struct {
	VaultName string `yaml:"vault"`
	CName string `yaml:"cname"`
	CertPath string `yaml:"cert"`
	DefaultDuration string `yaml:"default-duration"`
}

type certspec struct {
	InternalCerts []internal_cert `yaml:"internal-certs"`
	ExternalCerts []external_cert `yaml:"external-certs"`
	CAs map[string]internal_ca `yaml:"internal-cas"`
	Notify string `yaml:"notify"`
	NotifyHook string `yaml:"notify-hook"`
	Refresh string `yaml:"refresh"`
	Vaults map[string]vault `yaml:"vaults"`
}

type secret struct {
	Params map[string]string `json:"data"`
}

func  getConf() certspec {
	var c certspec
	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func notify(message string) {
	var notify_hook = "https://hooks.slack.com/services/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"
	var client = &http.Client{Timeout: time.Second * 10}
	var body = fmt.Sprintf(`{"text": "%s"}`, message)
	client.Post(notify_hook, "application/json", bytes.NewBuffer([]byte(body)))
}

func doExternal(keypath string,
				certpath string,
				combinedpath string,
				secretpath string,
	            vaultspec vault) {
	// grab the secret object from vault
	var vaultUrl = vaultspec.Url
	var fullUrl = fmt.Sprintf("%s/v1/%s", vaultUrl, secretpath)
	var client = &http.Client{Timeout: time.Second * 10}
	var req *http.Request
	var resp *http.Response
	var err error
	req, err = http.NewRequest("GET", fullUrl, nil)
	if err != nil {
		log.Printf("Failed to create request #%v ", err)
		panic("")
	}
	req.Header.Add("X-Vault-Token", vaultspec.Token)
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("Failed to send request #%v ", err)
		panic("")
	}
	fmt.Println(resp)
	defer resp.Body.Close()
	var data secret
	json.NewDecoder(resp.Body).Decode(&data)
	fmt.Println(data.Params["key"])
	fmt.Println(data.Params["cert"])

	// check the cert date
	block, _ := pem.Decode([]byte(data.Params["cert"]))
	if block == nil {
	    panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
	    panic("failed to parse certificate: " + err.Error())
	}
	var now = time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		var message string = fmt.Sprintf("Cert in %s is invalid: time now is %s, NotBefore is %s, NotAfter is %s\n",
					certpath, now.String(), cert.NotBefore.String(), cert.NotAfter.String())
		notify(message)
		return
	}
	fmt.Printf("Cert in %s is valid: time now is %s, NotBefore is %s, NotAfter is %s\n",
				certpath, now.String(), cert.NotBefore.String(), cert.NotAfter.String())

	// save it to disk
	ioutil.WriteFile(keypath, []byte(data.Params["key"]), 0600)
	ioutil.WriteFile(certpath, []byte(data.Params["cert"]), 0644)
	var combined = fmt.Sprintf("%s\n%s", data.Params["cert"], data.Params["key"])
	fmt.Println(combined)
	fmt.Println(combinedpath)
	ioutil.WriteFile(combinedpath, []byte(combined), 0600)
}

func doInternal(keypath string,
				certpath string,
				combinedpath string,
				cname string,
				ca_name string,
				ca internal_ca,
				vaultspec vault) {
	// read the cert from disk if it's there
	certBytes, err := ioutil.ReadFile(certpath)
	if err == nil {
		// check the expiration
		block, _ := pem.Decode(certBytes)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		var now = time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			var message string = fmt.Sprintf("Cert in %s is invalid: time now is %s, NotBefore is %s, NotAfter is %s\n",
						certpath, now.String(), cert.NotBefore.String(), cert.NotAfter.String())
			notify(message)
		} else {
			fmt.Printf("Cert in %s is valid: time now is %s, NotBefore is %s, NotAfter is %s\n",
					certpath, now.String(), cert.NotBefore.String(), cert.NotAfter.String())
			// all's well, nothing to do
			return
		}
	} else {
		fmt.Printf("%s certfile doesn't exist, generating new...\n")
	}

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "test@example.com"
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	subj := pkix.Name{
		CommonName:         cname,
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	var csr bytes.Buffer
	pem.Encode(&csr, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	fmt.Println(csr.String())

	// send the csr to vault
	cleancsr := strings.Replace(csr.String(), "\n", "\\n", -1)
	body := fmt.Sprintf(`{"csr": "%s", "ttl": "5m"}`, cleancsr)
	fmt.Println(body)
	var vaultUrl = vaultspec.Url
	var fullUrl = fmt.Sprintf("%s/v1/%s/sign/internal", vaultUrl, ca_name)
	var client = &http.Client{Timeout: time.Second * 10}
	var req *http.Request
	var resp *http.Response
	req, err = http.NewRequest("POST", fullUrl, bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Printf("Failed to create request #%v ", err)
		panic("")
	}
	req.Header.Add("X-Vault-Token", vaultspec.Token)
	req.Header.Add("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("Failed to send request #%v ", err)
		panic("")
	}
	fmt.Println(resp)
}

func main() {
	f, err := os.OpenFile("certpolice.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}   
	defer f.Close()
	log.SetOutput(f)
	
	var c certspec
	c = getConf()

//	var certs = c.ExternalCerts
//	for _, cert := range certs {
//		fmt.Println("this one's external")
//		fmt.Println(cert)
//		fmt.Println(cert.VaultName)
//		var vault = c.Vaults[cert.VaultName]
//		fmt.Println(vault)
//
//		doExternal(cert.KeyPath, cert.CertPath, cert.CombinedPath, cert.SecretPath, vault)
//	}      
	var icerts = c.InternalCerts
	for _, cert := range icerts {
		fmt.Println("this one's internal")
		fmt.Println(cert)
		cname := cert.Name
		ca_name := cert.CAName
		keyfile := cert.KeyPath
		certfile := cert.CertPath
		combined := cert.CombinedPath
		ca := c.CAs[ca_name]
		vaultspec := c.Vaults[ca.VaultName]

		doInternal(keyfile, certfile, combined, cname, ca_name, ca, vaultspec)
	}      
}

