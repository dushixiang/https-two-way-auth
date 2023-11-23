package main

import (
	"crypto/rand"
	"fmt"
	"https-two-way-auth/client"
	"https-two-way-auth/server"
	"https-two-way-auth/utils"
	"log"
	"os"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	serverCACsr, serverCAKey, err := utils.LoadOrCreateCA("server-ca.crt", "server-ca.key")
	if err != nil {
		log.Fatal(err)
	}
	serverCert, serverKey, err := utils.SignCertWithCA(serverCACsr, serverCAKey, false, "localhost")
	if err != nil {
		log.Fatal(err)
	}
	os.WriteFile("server.crt", serverCert, 0755)
	os.WriteFile("server.key", serverKey, 0755)

	clientCACsr, clientCAKey, err := utils.LoadOrCreateCA("client-ca.crt", "client-ca.key")
	if err != nil {
		log.Fatal(err)
	}
	clientCert, clientKey, err := utils.SignCertWithCA(clientCACsr, clientCAKey, true, "localhost")
	if err != nil {
		fmt.Println(err)
		return
	}
	os.WriteFile("client.crt", clientCert, 0755)
	os.WriteFile("client.key", clientKey, 0755)

	// 将证书和私钥转换为 PKCS#12 格式，用于导入到本地计算机中测试浏览器
	certificate, fkey, err := utils.ParseCertAndPrivateKey(clientCert, clientKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	p12Data, err := gopkcs12.Legacy.WithRand(rand.Reader).Encode(fkey, certificate, nil, "password")
	if err != nil {
		fmt.Println("Encode pem to pkcs12 Error:", err)
		return
	}
	// 将 PKCS#12 数据保存到文件
	os.WriteFile("client.p12", p12Data, 0755)

	go func() {
		server.Serv()
	}()

	time.Sleep(time.Second)
	select {}
	client.Request()

}
