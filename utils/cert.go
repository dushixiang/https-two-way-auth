package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

// GeneratePrivateKey 生成 ECC 私钥
func GeneratePrivateKey() (key *ecdsa.PrivateKey) {
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return
}

func GenerateRootCA() *x509.Certificate {
	var rootCsr = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"银河系"},
			Province:           []string{"地球"},
			Locality:           []string{"地球"},
			Organization:       []string{"类型安全"},
			OrganizationalUnit: []string{"银河系类型安全公司"},
			CommonName:         "银河系类型安全公司根证书",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	return rootCsr
}

func LoadOrCreateCA(crt, key string) (*x509.Certificate, crypto.Signer, error) {
	if !pathExists(crt) {
		// 文件不存在，自动生成一个
		rootCA := GenerateRootCA()
		priv := GeneratePrivateKey()

		cert, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, priv.Public(), priv)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(crt, pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644); err != nil {
			return nil, nil, err
		}

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(key, pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400); err != nil {
			return nil, nil, err
		}
	}

	certPEMBlock, err := os.ReadFile(crt)
	if err != nil {
		return nil, nil, err
	}

	keyPEMBlock, err := os.ReadFile(key)
	if err != nil {
		return nil, nil, err
	}

	return ParseCertAndPrivateKey(certPEMBlock, keyPEMBlock)
}

func SignCertWithCA(rootCA *x509.Certificate, privateKey crypto.Signer, isClient bool, domains ...string) ([]byte, []byte, error) {
	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	expiration := time.Now().AddDate(2, 3, 0)

	var csr = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            rootCA.Subject.Country,
			Province:           rootCA.Subject.Province,
			Locality:           rootCA.Subject.Locality,
			Organization:       rootCA.Subject.Organization,
			OrganizationalUnit: rootCA.Subject.OrganizationalUnit,
			CommonName:         rootCA.Subject.CommonName,
		},
		IPAddresses:           nil,
		DNSNames:              domains,
		NotBefore:             time.Now(),
		NotAfter:              expiration,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if isClient {
		csr.Subject.CommonName = "银河系类型安全公司客户端证书"
		csr.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		csr.Subject.CommonName = "银河系类型安全公司服务端证书"
	}

	der, err := x509.CreateCertificate(rand.Reader, csr, rootCA, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	var privPEM []byte
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		privDER := x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	case x509.ECDSA:
		privDER, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, nil, err
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	default:
		return nil, nil, errors.New("failed to sign cert, unsupported algorithm:" + cert.PublicKeyAlgorithm.String())
	}

	return certPEM, privPEM, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ParseCertAndPrivateKey(certBytes, privateKeyBytes []byte) (*x509.Certificate, crypto.Signer, error) {
	certDERBlock, _ := pem.Decode(certBytes)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to read the CA certificate: unexpected content")
	}
	caCert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyDERBlock, _ := pem.Decode(privateKeyBytes)
	if keyDERBlock == nil {
		return nil, nil, errors.New("failed to read the CA key: unexpected content")
	}

	var caKey interface{}
	switch keyDERBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyDERBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, errors.New("failed to read the CA key, unsupported type:" + keyDERBlock.Type)
	}

	switch caCert.PublicKeyAlgorithm {
	case x509.RSA:
		return caCert, caKey.(*rsa.PrivateKey), nil
	case x509.ECDSA:
		return caCert, caKey.(*ecdsa.PrivateKey), nil
	default:
		return nil, nil, errors.New("failed to read the CA key, unsupported algorithm:" + caCert.PublicKeyAlgorithm.String())
	}

}
