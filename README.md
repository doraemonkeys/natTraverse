



English|[中文](/README-ZH.md)  







## Tntroduction

A library for NAT traversal, support UDP/TCP, convenient implementation of p2p connection.

| peer1/peer2     | Full cone | Restricted Cone | Port Restricted Cone | Symetric          |
| --------------- | --------- | --------------- | -------------------- | ----------------- |
| Full cone       | ✓         | ✓               | ✓                    | Partial           |
| Restricted Cone | ✓         | ✓               | ✓                    | Partial           |
| Port Restricted | ✓         | ✓               | ✓                    | Partial           |
| Symetric        | Partial   | Partial         | Partial              | small probability |



## QuickStart

```go
go get -u github.com/Doraemonkeys/natTraverse
```



- A server with a public IP

```go
package main

import (
	"log"

	"github.com/Doraemonkeys/natTraverse"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

func main() {
	server := natTraverse.TraversalServer{
		ListenAddr: ":3711",
	}
	server.Run()
}
```



- peer1 and peer2

```go
package main

import (
	"fmt"
	"log"

	"github.com/Doraemonkeys/natTraverse"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

func main() {
	tool := natTraverse.TraversalTool{
		//WantNetwork: "tcp4",
		WantNetwork: "udp4",
		ServerAddr:  "serverIp",
		Token:       "12345678987654321",
		//LocalAddr:   ":3719",
	}
	TraversalInfo, err := tool.BeginTraversal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("success")
	fmt.Println("TraversalInfo:", TraversalInfo)
	laddr, _ := net.ResolveUDPAddr("udp4", TraversalInfo.Laddr)
	raddr, _ := net.ResolveUDPAddr("udp4", TraversalInfo.Raddr)
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	go func() {
		for {
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("recv:", string(buf[:n]))
		}
	}()
	fmt.Printf("you can send message to %s\n", raddr.String())
	for {
		var msg string
		fmt.Scan(&msg)
		_, err = conn.Write([]byte(msg))
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}
```

