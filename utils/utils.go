package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// 判断本地端口是否被占用(未占用会阻塞1秒等待超时，慎用)。
// Determine whether the local port is occupied (not occupied will block for 1 second to wait for timeout, be careful)
func IsPortInUse(port string) bool {
	if !strings.Contains(port, ":") {
		port = ":" + port
	}
	conn, err := net.DialTimeout("tcp", port, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// Setup a bare-bones TLS config for the server
//
//	 例如:添加quic协议支持
//		config.NextProtos = append(config.NextProtos, "quic")
func GenerateTLSConfig() (*tls.Config, error) {
	tlsCert, err := GenCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}

func GenCertificate() (cert tls.Certificate, err error) {
	rawCert, rawKey, err := GenerateKeyPair()
	if err != nil {
		return
	}
	return tls.X509KeyPair(rawCert, rawKey)
}

func GenerateKeyPair() (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"doraemon"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}

// 为函数调用添加超时
func WithTimeout[T any](d time.Duration, f func() ([]T, error)) ([]T, error) {
	c := make(chan []T, 1)
	e := make(chan error, 1)
	go func() {
		data, err := f()
		c <- data
		e <- err
	}()
	select {
	case data := <-c:
		return data, nil
	case err := <-e:
		return nil, err
	case <-time.After(d):
		return nil, fmt.Errorf("timeout")
	}
}

func WithTimeout2[T any](d time.Duration, f func() (T, error)) (T, error) {
	c := make(chan T, 1)
	e := make(chan error, 1)
	go func() {
		data, err := f()
		c <- data
		e <- err
	}()
	var temp T
	select {
	case data := <-c:
		return data, nil
	case err := <-e:
		return temp, err
	case <-time.After(d):
		return temp, fmt.Errorf("timeout")
	}
}

// only support udp4
// func QuicDial(laddr string, raddr string) (quic.Connection, error) {
// 	tlsConf := &tls.Config{
// 		InsecureSkipVerify: true,
// 		//NextProtos是一个支持的应用层协议列表，按照优先级顺序排列
// 		NextProtos: []string{"quic"},
// 	}
// 	udpConn, err := net.ListenPacket("udp4", laddr)
// 	if err != nil {
// 		return nil, err
// 	}
// 	remoteAddr, err := net.ResolveUDPAddr("udp4", raddr)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return quic.Dial(udpConn, remoteAddr, "", tlsConf, nil)
// }
