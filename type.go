package natTraverse

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type NATType int

func (n NATType) String() string {
	switch n {
	case None:
		return "None"
	case FullCone:
		return "FullCone"
	case RestrictedCone:
		return "RestrictedCone"
	case FullOrRestrictedCone:
		return "FullOrRestrictedCone"
	case PortRestrictedCone:
		return "PortRestrictedCone"
	case Symmetric:
		return "Symmetric"
	case UnKnown:
		return "UnKnown"
	default:
		return "UnKnown"
	}
}

func PraseNATType(natType string) (NATType, error) {
	switch natType {
	case "None":
		return None, nil
	case "FullCone":
		return FullCone, nil
	case "RestrictedCone":
		return RestrictedCone, nil
	case "FullOrRestrictedCone":
		return FullOrRestrictedCone, nil
	case "PortRestrictedCone":
		return PortRestrictedCone, nil
	case "Symmetric":
		return Symmetric, nil
	case "UnKnown":
		return UnKnown, nil
	case strconv.Itoa(int(None)):
		return None, nil
	case strconv.Itoa(int(FullCone)):
		return FullCone, nil
	case strconv.Itoa(int(RestrictedCone)):
		return RestrictedCone, nil
	case strconv.Itoa(int(FullOrRestrictedCone)):
		return FullOrRestrictedCone, nil
	case strconv.Itoa(int(PortRestrictedCone)):
		return PortRestrictedCone, nil
	case strconv.Itoa(int(Symmetric)):
		return Symmetric, nil
	case strconv.Itoa(int(UnKnown)):
		return UnKnown, nil
	default:
		return UnKnown, fmt.Errorf("unknown nat type %s", natType)
	}
}

const (
	UnKnown NATType = iota
	None
	FullCone
	RestrictedCone
	FullOrRestrictedCone
	PortRestrictedCone
	Symmetric
)

type TraversalInfo struct {
	LocalNat  NATTypeINfo
	RemoteNat NATTypeINfo
	//The local address where the udp hole was successfully punched.
	Laddr string
	//The remote address where the udp hole was successfully punched.
	Raddr string
	//UDPConn *net.UDPConn
	TCPConn *net.TCPConn
}

type TraversalTool struct {
	// WantNetwork is "udp4" or "tcp4",which is the type of network you want to penetrate.
	WantNetwork string
	//服务器地址，用于连接服务器。
	ServerAddr string
	// The token is used to match another host that connects to the local host point-to-point.
	// The two hosts that want to connect to the local host must have the same token.
	Token     string
	LocalAddr string
	Predictor PortPredictor
	NATInfo   NATTypeINfo
	//TCP打洞时的超时时间
	TCPTimeout time.Duration
	//测试NAT类型的时候用,随机产生，服务器用于标识客户端
	identityToken string
}

type PortPredictor interface {
	NextPort() string
	SetInitialPort(port string)
}

// LinearPortPredictor is a port predictor that predicts the next port by adding 1 to the current port.
type LinearPortPredictor struct {
	port int
}

func (d *LinearPortPredictor) NextPort() string {
	d.port++
	return fmt.Sprintf("%d", d.port)
}

func (d *LinearPortPredictor) SetInitialPort(port string) {
	d.port, _ = strconv.Atoi(port)
}

type TraversalServer struct {
	ListenAddr    string
	targetMap     map[string]chan Message
	targetMapLock *sync.Mutex
	tonkenMap     map[string]chan holePunchingConnection
	tonkenMapLock *sync.Mutex
}

var LocalNatType = NATTypeINfo{NATType: UnKnown}

type MsgType int

// 定义消息类型
const (
	TestNatType                  MsgType = iota //测试Nat类型
	ErrorResponse                               //服务端回复错误信息
	Connection                                  //客户端告诉服务端我想开始打洞
	ACK                                         //确认收到消息,可以重构为使用可靠udp
	PortNegotiation                             //告诉客户端服务端新建的监听端口
	PortNegotiationResponse                     //对PortNegotiation的响应
	ServerPortChangeTest                        // 服务器端口变化发送消息测试
	ServerPortChangeTestResponse                // 服务器端口变化发送消息测试响应
	EndResult                                   //Nat类型测试结果
	ProtocolChangeTest
	PunchingNegotiation // 用于打洞时协商交换信息
	StartPunching       //双方开始打洞
	Empty               //空消息
	ConnectionAck       //连接确认,用于打洞的双方确认连接
)

type Message struct {
	Type          MsgType `json:"type"`
	IdentityToken string  `json:"identitiy_token"`
	ErrorInfo     string  `json:"error_info"`
	Data          []byte  `json:"data"`
	// 由接收方填写，用于标识接收方的公网地址
	SrcPublicAddr string `json:"src_public_addr"`
}

type PortChange int

const (
	//端口线性增长(默认为UDP端口增长规律和TCP一致)
	Linear PortChange = iota + 100
	//端口随机增长
	Random
	UnKnownRule
)

type NATTypeINfo struct {
	NATType                  NATType    `json:"nat_type"`
	PortInfluencedByProtocol bool       `json:"port_influenced_by_protocol"`
	PortChangeRule           PortChange `json:"port_change_rule"`
}
