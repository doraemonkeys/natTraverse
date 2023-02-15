



## 简介

一个用于NAT穿透的库，支持UDP/TCP，方便实现p2p连接。

| peer1/peer2     | Full cone | Restricted Cone | Port Restricted Cone | Symetric          |
| --------------- | --------- | --------------- | -------------------- | ----------------- |
| Full cone       | ✓         | ✓               | ✓                    | Partial           |
| Restricted Cone | ✓         | ✓               | ✓                    | Partial           |
| Port Restricted | ✓         | ✓               | ✓                    | Partial           |
| Symetric        | Partial   | Partial         | Partial              | small probability |



## 如何使用

```go
go get -u github.com/Doraemonkeys/natTraverse
```



- 拥有公网IP的服务器

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
}
```

