package natTraverse

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Doraemonkeys/reliableUDP"
	"github.com/google/uuid"
	reuse "github.com/libp2p/go-reuseport"
)

// package natTraverse
//网络地址转换（Network Address Translation，NAT）
//内网穿透 Intranet penetration，nat_traversal
// Full cone NAT
// Restricted cone NAT
// Port restricted cone NAT
// Symmetric NAT
// influenced by protocol
// udp hole punching

func (t *TraversalTool) GetMyNatType() (NATTypeINfo, error) {
	rand.Seed(int64(time.Now().Nanosecond()))
	if t.identityToken == "" {
		t.identityToken = uuid.New().String()
	}
	if t.LocalAddr == "" {
		t.LocalAddr = ":" + fmt.Sprint(rand.Intn(20000)+10000)
	}
	udpConn, err := UDPRandListen()
	if err != nil {
		return NATTypeINfo{}, fmt.Errorf("listen udp error %w", err)
	}
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
	defer rudpConn.Close()
	if LocalNatType.NATType != UnKnown {
		t.NATInfo = LocalNatType
		return LocalNatType, nil
	}
	t.NATInfo.NATType = UnKnown
	msg := Message{
		Type:          TestNatType,
		IdentityToken: t.identityToken,
	}
	err = RUDPSendMessage(rudpConn, t.ServerAddr, msg, t.testNATTimeout)
	if err != nil {
		return NATTypeINfo{}, fmt.Errorf("connect to server error %w", err)
	}
	fmt.Println("send test nat type message")
	return t.beginTestNatType(rudpConn)
}

func (t *TraversalTool) BeginTraversal() (TraversalInfo, error) {
	if LocalNatType.NATType == UnKnown {
		t.testNATTimeout = 10 * time.Second
		natType, err := t.GetMyNatType()
		if err != nil {
			return TraversalInfo{}, fmt.Errorf("get nat type error %w", err)
		}
		LocalNatType = natType
		t.NATInfo = natType
	}
	fmt.Println("nat type", t.NATInfo.NATType.String())
	fmt.Println("port change rule", t.NATInfo.UDPPortChangeRule)
	fmt.Println("PortInfluencedByProtocol", t.NATInfo.PortInfluencedByProtocol)
	rand.Seed(int64(time.Now().Nanosecond()))
	if t.LocalAddr == "" {
		t.LocalAddr = ":" + fmt.Sprint(rand.Intn(20000)+10000)
	}
	fmt.Println("rand local addr", t.LocalAddr)
	t.WantNetwork = strings.ToLower(t.WantNetwork)
	if t.WantNetwork != "udp4" && t.WantNetwork != "tcp4" {
		return TraversalInfo{}, fmt.Errorf("only support udp4 and tcp4")
	}
	if t.TCPTimeout == 0 {
		t.TCPTimeout = 8 * time.Second
	}
	if t.UDPTimeout == 0 {
		t.UDPTimeout = 8 * time.Second
	}
	return t.traversal()
}

func (t *TraversalTool) traversal() (TraversalInfo, error) {
	var token string
	switch t.WantNetwork {
	case "udp4":
		token = t.Token + "UDP"
	case "tcp4":
		token = t.Token + "TCP"
	}
	tcpConn, err := net.Dial("tcp4", t.ServerAddr)
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("dial tcp error %w", err)
	}
	msg := Message{
		Type:          Connection,
		IdentityToken: token,
	}
	data, err := json.Marshal(t.NATInfo)
	if err != nil {
		return TraversalInfo{}, err
	}
	msg.Data = data
	err = TCPSendMessage(tcpConn.(*net.TCPConn), msg)
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("send message error %w", err)
	}
	//接收ACK，用于服务器判断我方是否仍然在线
	msg, err = TCPReceiveMessage(tcpConn.(*net.TCPConn))
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("receive message error %w", err)
	}
	if msg.Type == ErrorResponse {
		return TraversalInfo{}, fmt.Errorf("receive error response %s", msg.ErrorInfo)
	}
	if msg.Type != ACK {
		return TraversalInfo{}, fmt.Errorf("receive wrong message type %d", msg.Type)
	}
	fmt.Println("received ack")
	//接收穿透信息holePunchingNegotiationMsg
	log.Println("now receive punching info...")
	msg, err = TCPReceiveMessage(tcpConn.(*net.TCPConn))
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("receive message error %w", err)
	}
	if msg.Type == ErrorResponse {
		return TraversalInfo{}, fmt.Errorf("receive error response: %s", msg.ErrorInfo)
	}
	if msg.Type != PunchingNegotiation {
		return TraversalInfo{}, fmt.Errorf("receive wrong message type %d", msg.Type)
	}
	var punchingInfo holePunchingNegotiationMsg
	fmt.Println("punching info", string(msg.Data))
	err = punchingInfo.unmarshal(msg.Data)
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("unmarshal punching info error %w", err)
	}
	if t.Predictor == nil && punchingInfo.RNAT.UDPPortChangeRule == Linear {
		t.Predictor = &LinearPortPredictor{}
	}
	switch t.WantNetwork {
	case "udp4":
		return t.traversalUDP(tcpConn.(*net.TCPConn), punchingInfo)
	case "tcp4":
		return t.traversalTCP(tcpConn.(*net.TCPConn), punchingInfo)
	default:
		return TraversalInfo{}, fmt.Errorf("only support udp4 and tcp4")
	}
}

func (t *TraversalTool) traversalTCP(tcpConn *net.TCPConn, punchingInfo holePunchingNegotiationMsg) (TraversalInfo, error) {
	addrChan := make(chan string, 1)
	go func() {
		newServerAddr := t.ServerAddr[:strings.LastIndex(t.ServerAddr, ":")+1] + punchingInfo.ServerPort
		fmt.Println("newServerAddr", newServerAddr)
		//让服务器获取t.LocalAddr在NAT中的映射公网地址
		c, err := reuse.Dial("tcp4", t.LocalAddr, newServerAddr)
		if err != nil {
			fmt.Println("dial tcp error", err)
			return
		}
		c.Close()
		//接收服务器返回的对方公网地址:新端口
		msg, err := TCPReceiveMessage(tcpConn)
		if err != nil {
			fmt.Println("receive message error", err)
			return
		}
		if msg.Type != StartPunching {
			fmt.Println("receive message type error", msg.Type)
			return
		}
		addrChan <- string(msg.Data)
		//addrChan <- string(msg.Data)
	}()

	//var isSameNAT bool = false
	// if punchingInfo.MyPublicAddr[:strings.LastIndex(punchingInfo.MyPublicAddr, ":")] == punchingInfo.RPublicAddr[:strings.LastIndex(punchingInfo.RPublicAddr, ":")] {
	// 	fmt.Println("is same nat")
	// 	isSameNAT = true
	// }
	var targetRemoteAddr string
	select {
	case <-time.After(t.TCPTimeout):
		return TraversalInfo{}, fmt.Errorf("receive remote public addr timeout")
	case targetRemoteAddr = <-addrChan:
		fmt.Println("targetRemoteAddr", targetRemoteAddr)
	}
	if t.NATInfo.NATType == Symmetric || punchingInfo.RNAT.NATType == Symmetric {
		return TraversalInfo{}, fmt.Errorf("symmetric nat not support tcp")
	}
	// if t.NATInfo.NATType == Symmetric {
	// 	switch punchingInfo.RNAT.NATType {
	// 	case Symmetric:
	// 		if punchingInfo.MyType == passive {
	// 			return t.passiveBothSymmetric_TCP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
	// 		}
	// 		return t.activeBothSymmetric_TCP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
	// 	case FullCone, RestrictedCone, PortRestrictedCone:
	// 		return t.SymmetricToPortRestrict_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
	// 	default:
	// 		return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
	// 	}
	// } else {
	// 	switch punchingInfo.RNAT.NATType {
	// 	case Symmetric:
	// 		return t.PortRestrictToSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
	// 	case FullCone, RestrictedCone, PortRestrictedCone:
	// 		if punchingInfo.MyType == passive {
	// 			return t.passiveBothNoSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
	// 		}
	// 		return t.activeBothNoSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
	// 	default:
	// 		return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
	// 	}
	// }
	return t.bothNoSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
}

func (t *TraversalTool) traversalUDP(tcpConn *net.TCPConn, punchingInfo holePunchingNegotiationMsg) (TraversalInfo, error) {
	addrChan := make(chan string, 1)
	go func() {
		newServerAddr := t.ServerAddr[:strings.LastIndex(t.ServerAddr, ":")+1] + punchingInfo.ServerPort
		fmt.Println("newServerAddr", newServerAddr)
		lAddr, err := net.ResolveUDPAddr("udp4", t.LocalAddr)
		if err != nil {
			return
		}
		udpConn, err := net.ListenUDP("udp4", lAddr)
		if err != nil {
			return
		}
		rudpConn := reliableUDP.NewReliableUDP(udpConn)
		defer rudpConn.Close()
		err = RUDPSendMessage(rudpConn, newServerAddr, Message{Type: Empty}, t.UDPTimeout)
		if err != nil {
			fmt.Println("send empty message error", err)
			return
		}
		msg, err := TCPReceiveMessage(tcpConn)
		if err != nil {
			fmt.Println("receive message error", err)
			return
		}
		if msg.Type == ErrorResponse {
			log.Println("remote peer error", msg.ErrorInfo)
			return
		}
		if msg.Type != StartPunching {
			fmt.Println("receive message type error", msg.Type, string(msg.Data))
			return
		}
		addrChan <- string(msg.Data)
	}()

	var isSameNAT bool = false
	if punchingInfo.MyPublicAddr[:strings.LastIndex(punchingInfo.MyPublicAddr, ":")] == punchingInfo.RPublicAddr[:strings.LastIndex(punchingInfo.RPublicAddr, ":")] {
		fmt.Println("is same nat")
		isSameNAT = true
	}
	var targetRemoteAddr string
	select {
	case <-time.After(t.UDPTimeout):
		return TraversalInfo{}, fmt.Errorf("receive remote public addr timeout")
	case targetRemoteAddr = <-addrChan:
		fmt.Println("targetRemoteAddr", targetRemoteAddr)
	}
	if t.NATInfo.NATType == Symmetric {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			if punchingInfo.MyType == passive {
				//return t.passiveBothSymmetric_UDP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
				return t.passiveBothSymmetric_UDP2(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
			}
			//return t.activeBothSymmetric_UDP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
			return t.activeBothSymmetric_UDP2(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
		case FullCone, RestrictedCone, PortRestrictedCone:
			return t.symmetricToPortRestrict_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		default:
			return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
		}
	} else {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			return t.portRestrictToSymmetric_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		case FullCone, RestrictedCone, PortRestrictedCone:
			if punchingInfo.MyType == passive {
				return t.passiveBothNoSymmetric_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
			}
			return t.activeBothNoSymmetric_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		default:
			return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
		}
	}
}

func (t *TraversalTool) beginTestNatType(rudpConn *reliableUDP.ReliableUDP) (NATTypeINfo, error) {
	rudpConn.SetGlobalReceive()
	for {
		msg, _, err := RUDPReceiveAllMessage(rudpConn, t.testNATTimeout)
		if err != nil {
			return NATTypeINfo{}, fmt.Errorf("receive message error %w", err)
		}
		switch msg.Type {
		case PortNegotiation: //端口协商，向改变的端口发送消息，若服务器收到的地址端口改变，则说明是Symmetric NAT
			err := t.handlePortNegotiation(rudpConn, msg)
			if err != nil {
				return NATTypeINfo{}, err
			}
			err = t.protocolChangeTest(rudpConn)
			if err != nil {
				return NATTypeINfo{}, err
			}
		case ACK: //服务器确认收到消息
			// log.Println("receive ack from", raddr.String())
		case EndResult: //服务器确认NAT类型发回最终结果
			err := t.handleEndResult(msg)
			if err != nil {
				return NATTypeINfo{}, err
			}
			return t.NATInfo, nil //结束
		case ErrorResponse: //服务器返回错误信息
			return NATTypeINfo{}, fmt.Errorf("error response %s", msg.ErrorInfo)
		case ServerPortChangeTest: //服务器端口改变测试
			err := t.handleServerPortChangeTest(rudpConn)
			if err != nil {
				return NATTypeINfo{}, err
			}
		default:
			return NATTypeINfo{}, fmt.Errorf("unknown message type %d", msg.Type)
		}
	}
}

func (t *TraversalTool) protocolChangeTest(rudpConn *reliableUDP.ReliableUDP) error {
	laddr, err := net.ResolveTCPAddr("tcp4", rudpConn.LocalAddr().String())
	if err != nil {
		log.Println("resolve tcp addr error", err)
		return err
	}
	rddr, err := net.ResolveTCPAddr("tcp4", t.ServerAddr)
	if err != nil {
		log.Println("resolve tcp addr error", err)
		return err
	}
	tcpConn, err := net.DialTCP("tcp4", laddr, rddr)
	if err != nil {
		log.Println("dial tcp error", err)
		return err
	}
	defer tcpConn.Close()
	msg := Message{
		Type:          ProtocolChangeTest,
		IdentityToken: t.identityToken,
	}
	err = TCPSendMessage(tcpConn, msg)
	if err != nil {
		log.Println("send message error", err)
		return err
	}
	fmt.Println("send protocol change test")
	return nil
}

func (t *TraversalTool) handleServerPortChangeTest(rudpConn *reliableUDP.ReliableUDP) error {
	msg := Message{
		Type:          ServerPortChangeTestResponse,
		IdentityToken: t.identityToken,
	}
	err := RUDPSendMessage(rudpConn, t.ServerAddr, msg, t.UDPTimeout)
	if err != nil {
		return fmt.Errorf("serverPortChangeTestResponse error %w", err)
	}
	return nil
}

func (t *TraversalTool) handlePortNegotiation(rudpConn *reliableUDP.ReliableUDP, msg Message) error {
	var port = string(msg.Data)
	tempAddr := t.ServerAddr[:strings.LastIndex(t.ServerAddr, ":")+1] + port
	fmt.Println("temp addr", tempAddr)
	msg = Message{
		Type:          PortNegotiationResponse,
		IdentityToken: t.identityToken,
	}
	err := RUDPSendMessage(rudpConn, tempAddr, msg, t.UDPTimeout)
	if err != nil {
		log.Println("port negotiation response error", err)
		return fmt.Errorf("send message error %w", err)
	}
	fmt.Println("send port negotiation response")
	return nil
}

func (t *TraversalTool) handleEndResult(msg Message) error {
	if msg.ErrorInfo != "" {
		log.Println("error response", msg.ErrorInfo)
		return fmt.Errorf("error response %s", msg.ErrorInfo)
	}
	var err error
	var natInfo NATTypeINfo
	err = json.Unmarshal(msg.Data, &natInfo)
	if err != nil {
		log.Println("unmarshal nat info error", err)
		return fmt.Errorf("unmarshal nat info error %w", err)
	}
	t.NATInfo = natInfo
	return nil
}
