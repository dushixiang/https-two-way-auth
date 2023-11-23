
双向认证的含义就是服务端和客户端都需要验证对方的身份，相比普通的单向认证多了一些步骤。

## 基础概念

下面先讲一些 https 相关的概念。

**对称加密**

对称加密是一种加密算法，使用相同的密钥来加密和解密数据。
这意味着发送和接收方都必须共享相同的密钥。
对称加密是加密领域中最快的一种加密方式，因为它使用的是相对较小的密钥和简单的运算。

**非对称加密**

非对称加密是一种密码学方法，与对称加密不同，它使用一对密钥而不是一个密钥。
这对密钥包括一个公钥和一个私钥。公钥用于加密数据，而私钥用于解密数据。

- 公钥： 公钥是一个用于加密的密钥，可以公开被任何人访问，公钥加密的数据只有私钥可以解开。
- 私钥： 私钥是与公钥配对的另一个密钥，需要妥善保管避免被泄露。
- 加密和解密： 如果使用公钥加密了一段数据，只有拥有相应私钥的人才能解密它。反之亦然，如果使用私钥加密了数据，只有拥有相应公钥的人才能解密。
- 数字签名：简单点说数字签名就是私钥加密摘要，而非加密原文，分为下面几个步骤：
  1. 消息摘要：使用哈希算法把原文生成一份摘要。
  2. 私钥加密：使用私钥对摘要进行加密，得到数字签名。
  3. 发送消息和签名：把原数据和加密后的数据摘要打包一起发给对方。
  4. 验证：接收方使用发送方的公钥来解密数字签名，得到摘要。然后接收方对收到的消息使用同样的哈希算法得到一个新的摘要。如果这两个摘要匹配，说明消息未被篡改，且确实是由私钥的所有者签名的。

RSA、DSA、ECDSA 和 Elliptic Curve Diffie-Hellman (ECDH) 是一些常见的非对称加密算法。
这些算法每个有其独特的优点和应用场景，比如 RSA 用于数字签名，ECDH 适用于密钥协商。
与对称加密相比，非对称加密算法的性能都比较低。

**证书**

- CA：也就是常说的根证书，操作系统默认集成了很多权威机构的根证书，因此不必再自己安装和信任一遍。
- https 证书：通常包括一个公钥证书和一个私钥，它们由权威机构（CA）签发，这些权威机构通常是要收费的，也有免费的机构，类似[Let's Encrypt](https://letsencrypt.org/)。
  另一种方式是自己签发，不过需要让客户端信任自己签发的CA证书，目的是为了让自己签发的域名证书通过校验。
- 证书签发：就是用权威机构帮你生成一个私钥，并使用它的根证书和这个私钥对你的域名进行证书签发，最后将签发后的公钥证书和这个私钥给你。

证书是建立信任的关键，包括 CA 根证书、https 证书和自签名证书。CA 提供权威认证，而自签名证书适用于开发环境。

**https 通信步骤**

https 通信大致上是分为3个阶段。

1. 握手阶段（Handshake）：
    - 客户端向服务器发送一个加密通信的请求，请求中包含支持的加密算法和其他相关信息。
    - 服务器将自己的证书、支持的加密算法等信息发送给客户端。
    - 客户端验证服务器的证书是否有效。
2. 密钥协商阶段：
    - 利用非对称加密算法使得双方安全的获取到一个会话密钥。
3. 加密通信阶段：
    - 客户端和服务器使用协商好的会话密钥进行对称加密通信，保护数据的机密性。

**配置https证书**

常见的web服务器都有配置https证书的功能，例如 nginx、caddy等。

基本上只需要把证书和私钥配置到某一个目录，更改web服务器的配置即可生效。

**https单向认证**

顾名思义，就是只有一个方向进行了认证，这里指的是客户端认证，通常浏览器都会对网站上的https证书进行验证。

正常情况下访问https站点，浏览器左上角的小锁就会是灰色的。（如果你的浏览器版本过低，有可能是绿色的。）

当 https 站点的证书不正确时，就会出现一个出现【不安全】这个三个红色的大字，有下面几种原因会导致不安全。

1. 当前域名和证书签名的域名不匹配。（这种情况就需要重新进行域名签发了。）
2. 当前IP和证书签名的IP不匹配。（这种情况较少，因为之前市面上的机构都不签发IP证书，现在好像也有了不少。）
3. 证书过期了。（需要定期检查域名是否过期并及时更新）

**https双向认证**

与https单向认证不同的是，服务端也会要求验证客户端的证书，除了域名证书和私钥外（开启https用），还需要一张客户端CA证书用于验证客户端提供的普通证书。

客户端在访问服务端时，需要将自己的证书发送给对方，经过服务端的验证后才能够正常通信。

客户端证书认证提供额外的安全层，确保只有授权的客户端能够连接。生成和管理客户端证书时，需要采取措施保护私钥，确保其不被泄露。

效果如下图所示：

![https-two-way-auth-demo](https://oss.typesafe.cn/blog/https-two-way-auth.png)

## golang 实现 https 双向认证

**生成服务端CA证书，域名证书和私钥**

> 具体的生成证书部分代码可以查看文章末尾的 GitHub 仓库。

```go
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
```

**生成服务端CA证书，普通证书和私钥**
```go
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
```

**导入证书**

如果你想要用浏览器体验双向认证，还需要把客户端证书和私钥转换成p12证书并导入到本地计算机中。

```go
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
```

这里就不再赘述如何导入了，和导入抓包软件CA证书的流程是相同的。

**配置服务端**

```go
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "OK")
}

func Serv() {
	http.HandleFunc("/", handler)

	// 服务器证书和私钥
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Println(err)
		return
	}

	// 客户端 CA 证书池
	caCert, err := os.ReadFile("client-ca.crt")
	if err != nil {
		fmt.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// HTTPS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	fmt.Println("Server is running on https://localhost:8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Println(err)
	}
}
```

**配置客户端**

```go
package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func Request() {
	// 服务器 CA 证书池
	caCert, err := os.ReadFile("server-ca.crt")
	if err != nil {
		fmt.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 客户端证书和私钥
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		fmt.Println(err)
		return
	}

	// HTTPS 配置
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatal("get ", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("read ", err)
		return
	}

	fmt.Println(string(body))
}
```

此时提前说一句，如果你想要访问服务端https是安全的，还需要导入并信任服务端CA证书，原因上面已经说过。

## 认证过程

TLS v1.2 和 TLS v1.3 有很大不同，当然这些并不是最重要的，因为我们并不能改变或者控制这些协议。

我整理了 TLS v1.2 和 TLS v1.3 在双向认证的过程中不同的地方，如下图，仅供参考。

> 红色标记部分是双向认证时才有的通信步骤。


**TLS v1.2**

![https-tls-v1.2-two-way-auth](https://oss.typesafe.cn/blog/https-tls-v1.2-two-way-auth.png)

**TLS v1.3**

![https-tls-v1.3-two-way-auth](https://oss.typesafe.cn/blog/https-tls-v1.3-two-way-auth.png)

TLS v1.3 使用了 ECDH 等密钥协商算法，因此在交互的过程中只需要双方计算一个临时密钥并发送给对方，双方就能通过这个临时密钥计算出最终要使用的加密密钥。
减少了很多步骤，对于性能和安全性方便有着极大提高。

### golang 代码地址

https://github.com/dushixiang/https-two-way-auth