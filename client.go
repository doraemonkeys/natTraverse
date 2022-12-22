package natTraverse

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

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
	if LocalNatType.NATType != UnKnown {
		t.NATInfo = LocalNatType
		return LocalNatType, nil
	}
	t.NATInfo.NATType = UnKnown
	msg := Message{
		Type:          TestNatType,
		IdentityToken: t.identityToken,
	}
	//发送两次(第一个UDP包可能会被路由器丢弃)
	UDPSendMessage(udpConn, t.ServerAddr, msg)
	err = UDPSendMessage(udpConn, t.ServerAddr, msg)
	if err != nil {
		return NATTypeINfo{}, fmt.Errorf("send message error %w", err)
	}
	return t.beginTestNatType(udpConn)
}

func (t *TraversalTool) BeginTraversal() (TraversalInfo, error) {
	if LocalNatType.NATType == UnKnown {
		natType, err := t.GetMyNatType()
		if err != nil {
			return TraversalInfo{}, fmt.Errorf("get nat type error %w", err)
		}
		LocalNatType = natType
		t.NATInfo = natType
	}
	fmt.Println("nat type", t.NATInfo.NATType.String())
	fmt.Println("port change rule", t.NATInfo.PortChangeRule)
	fmt.Println("PortInfluencedByProtocol", t.NATInfo.PortInfluencedByProtocol)
	if t.Predictor == nil && t.NATInfo.PortChangeRule == Linear {
		t.Predictor = &LinearPortPredictor{}
	}
	rand.Seed(int64(time.Now().Nanosecond()))
	if t.LocalAddr == "" {
		t.LocalAddr = ":" + fmt.Sprint(rand.Intn(20000)+10000)
	}
	t.WantNetwork = strings.ToLower(t.WantNetwork)
	if t.WantNetwork != "udp4" && t.WantNetwork != "tcp4" {
		return TraversalInfo{}, fmt.Errorf("only support udp4 and tcp4")
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
	msg, err = TCPReceiveMessage(tcpConn.(*net.TCPConn))
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("receive message error %w", err)
	}
	if msg.Type == ErrorResponse {
		return TraversalInfo{}, fmt.Errorf("receive error response %s", msg.Data)
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
		_, err := reuse.Dial("tcp4", t.LocalAddr, newServerAddr)
		if err != nil {
			fmt.Println("dial tcp error", err)
			return
		}
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

	var isSameNAT bool = false
	if punchingInfo.MyPublicAddr[:strings.LastIndex(punchingInfo.MyPublicAddr, ":")] == punchingInfo.RPublicAddr[:strings.LastIndex(punchingInfo.RPublicAddr, ":")] {
		fmt.Println("is same nat")
		isSameNAT = true
	}
	var targetRemoteAddr string
	select {
	case <-time.After(5 * time.Second):
		return TraversalInfo{}, fmt.Errorf("receive remote public addr timeout")
	case targetRemoteAddr = <-addrChan:
		fmt.Println("targetRemoteAddr", targetRemoteAddr)
	}
	if t.NATInfo.NATType == Symmetric {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			if punchingInfo.MyType == passive {
				return t.passiveBothSymmetric_TCP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
			}
			return t.activeBothSymmetric_TCP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
		case FullCone, RestrictedCone, PortRestrictedCone:
			return t.SymmetricToPortRestrict_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		default:
			return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
		}
	} else {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			return t.PortRestrictToSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		case FullCone, RestrictedCone, PortRestrictedCone:
			if punchingInfo.MyType == passive {
				return t.passiveBothNoSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
			}
			return t.activeBothNoSymmetric_TCP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		default:
			return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
		}
	}
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
		rudpConn := NewReliableUDP(udpConn)
		defer rudpConn.Close()
		err = RUDPSendMessage(rudpConn, newServerAddr, Message{Type: Empty})
		if err != nil {
			fmt.Println("send empty message error", err)
			return
		}
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
	}()

	var isSameNAT bool = false
	if punchingInfo.MyPublicAddr[:strings.LastIndex(punchingInfo.MyPublicAddr, ":")] == punchingInfo.RPublicAddr[:strings.LastIndex(punchingInfo.RPublicAddr, ":")] {
		fmt.Println("is same nat")
		isSameNAT = true
	}
	var targetRemoteAddr string
	select {
	case <-time.After(5 * time.Second):
		return TraversalInfo{}, fmt.Errorf("receive remote public addr timeout")
	case targetRemoteAddr = <-addrChan:
		fmt.Println("targetRemoteAddr", targetRemoteAddr)
	}
	if t.NATInfo.NATType == Symmetric {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			if punchingInfo.MyType == passive {
				return t.passiveBothSymmetric_UDP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
			}
			return t.activeBothSymmetric_UDP(t.LocalAddr, targetRemoteAddr, isSameNAT, punchingInfo.RNAT)
		case FullCone, RestrictedCone, PortRestrictedCone:
			return t.SymmetricToPortRestrict_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
		default:
			return TraversalInfo{}, fmt.Errorf("unknown NAT type %s", punchingInfo.RNAT.NATType)
		}
	} else {
		switch punchingInfo.RNAT.NATType {
		case Symmetric:
			return t.PortRestrictToSymmetric_UDP(t.LocalAddr, targetRemoteAddr, punchingInfo.RNAT)
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

func (t *TraversalTool) passiveBothNoSymmetric_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	lAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	emptyMsg := Message{Type: Empty}
	rudpConn := NewReliableUDP(udpConn)
	defer rudpConn.Close()
	//这两个UDP的信息仅仅负责打洞，然后等待对方的连接
	RUDPSendUnreliableMessage(rudpConn, raddr, emptyMsg)
	err = RUDPSendUnreliableMessage(rudpConn, raddr, emptyMsg)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn.SetGlobalReceive()
	for {
		msg, newAddr, err := RUDPReceiveAllMessage(rudpConn, time.Second*2)
		if err != nil {
			return TraversalInfo{}, fmt.Errorf("hole punching error %w", err)
		}
		if newAddr.String() != raddr {
			log.Println("unexpected address", newAddr.String())
			continue
		}
		if msg.Type == ConnectionAck {
			endInfo := TraversalInfo{
				LocalNat:  t.NATInfo,
				RemoteNat: rNAT,
				Laddr:     laddr,
				Raddr:     raddr,
			}
			return endInfo, nil
		} else {
			log.Println("unexpected message", msg)
		}
	}
}

func (t *TraversalTool) activeBothNoSymmetric_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	lAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn := NewReliableUDP(udpConn)
	defer rudpConn.Close()
	mag := Message{Type: ConnectionAck}
	err = RUDPSendMessage(rudpConn, raddr, mag)
	if err != nil {
		return TraversalInfo{}, fmt.Errorf("send message error %w", err)
	}
	endInfo := TraversalInfo{
		LocalNat:  t.NATInfo,
		RemoteNat: rNAT,
		Laddr:     laddr,
		Raddr:     raddr,
	}
	return endInfo, nil
}

func (t *TraversalTool) passiveBothNoSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	//go  reuse.Dial("tcp4", laddr, raddr)
	go func() {
		c, err := reuse.Dial("tcp4", laddr, raddr)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(c.LocalAddr().String())
	}()
	Listener, err := reuse.Listen("tcp4", laddr)
	if err != nil {
		fmt.Println("listen tcp error", err)
		return TraversalInfo{}, err
	}
	tcpListener := Listener.(*net.TCPListener)
	tcpListener.SetDeadline(time.Now().Add(time.Second * 3))
	defer tcpListener.Close()
	tcpConn, err := tcpListener.AcceptTCP()
	if err != nil {
		return TraversalInfo{}, err
	}
	endInfo := TraversalInfo{
		LocalNat:  t.NATInfo,
		RemoteNat: rNAT,
		Laddr:     laddr,
		Raddr:     raddr,
		TCPConn:   tcpConn,
	}
	return endInfo, nil
}

func (t *TraversalTool) activeBothNoSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	tcpConn, err := net.DialTimeout("tcp4", raddr, time.Second*3)
	if err != nil {
		return TraversalInfo{}, err
	}
	endInfo := TraversalInfo{
		LocalNat:  t.NATInfo,
		RemoteNat: rNAT,
		Laddr:     laddr,
		Raddr:     raddr,
		TCPConn:   tcpConn.(*net.TCPConn),
	}
	return endInfo, nil
}

// 被动端，对方是对称NAT，打洞完成后，等待对方的连接
func (t *TraversalTool) PortRestrictToSymmetric_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	lAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn := NewReliableUDP(udpConn)
	defer rudpConn.Close()
	rudpConn.SetGlobalReceive()
	go func() {
		for i := 0; i < 20; i++ {
			rPort := t.Predictor.NextPort()
			new_rAddr := rIP + ":" + rPort
			fmt.Println("new_rAddr", new_rAddr)
			msg := Message{Type: ConnectionAck}
			RUDPSendUnreliableMessage(rudpConn, new_rAddr, msg)
			err = RUDPSendUnreliableMessage(rudpConn, new_rAddr, msg)
			if err != nil {
				fmt.Println("send message error", err)
			}
		}
	}()
	for {
		msg, addr, err := RUDPReceiveAllMessage(rudpConn, time.Second*3)
		if err != nil {
			return TraversalInfo{}, fmt.Errorf("receive message error %w", err)
		}
		if msg.Type == ConnectionAck {
			endInfo := TraversalInfo{
				LocalNat:  t.NATInfo,
				RemoteNat: rNAT,
				Laddr:     laddr,
				Raddr:     addr.String(),
			}
			return endInfo, nil
		}
	}
}

// 被动端，对方是对称NAT，打洞完成后，等待对方的连接
func (t *TraversalTool) PortRestrictToSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	go func() {
		for i := 0; i < 20; i++ {
			rPort := t.Predictor.NextPort()
			new_rAddr := rIP + ":" + rPort
			fmt.Println("new_rAddr", new_rAddr)
			go reuse.Dial("tcp4", laddr, new_rAddr)
		}
	}()

	Listener, err := reuse.Listen("tcp4", laddr)
	if err != nil {
		fmt.Println("listen tcp error", err)
		return TraversalInfo{}, err
	}
	tcpListener := Listener.(*net.TCPListener)
	tcpListener.SetDeadline(time.Now().Add(time.Second * 3))

	conn, err := tcpListener.AcceptTCP()
	if err != nil {
		fmt.Println("accept tcp error", err)
		return TraversalInfo{}, err
	}
	fmt.Println("accept tcp", conn.RemoteAddr().String())
	endInfo := TraversalInfo{
		Laddr:     conn.LocalAddr().String(),
		Raddr:     conn.RemoteAddr().String(),
		LocalNat:  t.NATInfo,
		RemoteNat: rNAT,
		TCPConn:   conn,
	}
	return endInfo, nil
}

func (t *TraversalTool) SymmetricToPortRestrict_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	tcpConn, err := reuse.Dial("tcp4", laddr, raddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	endInfo := TraversalInfo{
		Laddr:     tcpConn.LocalAddr().String(),
		Raddr:     tcpConn.RemoteAddr().String(),
		LocalNat:  t.NATInfo,
		RemoteNat: rNAT,
		TCPConn:   tcpConn.(*net.TCPConn),
	}
	return endInfo, nil
}

func (t *TraversalTool) SymmetricToPortRestrict_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	LAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", LAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn := NewReliableUDP(udpConn)
	defer rudpConn.Close()
	rudpConn.SetGlobalReceive()
	for i := 0; i < 3; i++ {
		err := RUDPSendMessage(rudpConn, raddr, Message{Type: ConnectionAck})
		if err != nil {
			fmt.Println("send message error", err)
			continue
		}
		endInfo := TraversalInfo{
			LocalNat:  t.NATInfo,
			RemoteNat: rNAT,
			Laddr:     laddr,
			Raddr:     raddr,
		}
		return endInfo, nil
	}
	return TraversalInfo{}, fmt.Errorf("hole punching failed, no response")
}

func (t *TraversalTool) activeBothSymmetric_UDP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	fmt.Println("activeBothSymmetric_UDP")
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	t.Predictor.NextPort()
	t.Predictor.NextPort()
	for i := 0; i < 9; i++ {
		t.Predictor.NextPort()
	}
	newRport := t.Predictor.NextPort()
	fmt.Println("newRport", newRport)
	newRaddr := rIP + ":" + newRport
	fmt.Println("newRaddr", newRaddr)
	randPort := rand.Intn(20000) + 10000
	fmt.Println("rand port:", randPort)
	infoChan := make(chan TraversalInfo, 1)
	if InSameNat {
		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
		fmt.Println("InSameNat, wait 1s")
		time.Sleep(time.Second)
	}
	for i := 0; i < 10; i++ {
		fmt.Println("dial newRaddr", newRaddr, "randPort", randPort)
		go SymmetricDail(newRaddr, randPort, infoChan)
		randPort++
	}
	for i := 0; i < 9; i++ {
		t.Predictor.NextPort()
	}
	newRport = t.Predictor.NextPort()
	fmt.Println("newRport", newRport)
	newRaddr = rIP + ":" + newRport
	fmt.Println("newRaddr", newRaddr)
	for i := 0; i < 10; i++ {
		//10个不同的本地地址向对方同一个地址发送连接请求
		fmt.Println("dial newRaddr", newRaddr, "randPort", randPort)
		go SymmetricDail(newRaddr, randPort, infoChan)
		randPort++
	}
	select {
	case endInfo := <-infoChan:
		endInfo.LocalNat = t.NATInfo
		endInfo.RemoteNat = rNAT
		return endInfo, nil
	case <-time.After(time.Second * 3):
		return TraversalInfo{}, fmt.Errorf("hole punching failed, no response")
	}
}

func SymmetricDail(raddr string, lport int, infoChan chan TraversalInfo) {
	lAddr, err := net.ResolveUDPAddr("udp4", ":"+strconv.Itoa(lport))
	if err != nil {
		fmt.Println("resolve udp addr error", err)
		return
	}
	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		fmt.Println("listen udp error", err)
		return
	}
	UDPSendMessage(udpConn, raddr, Message{Type: ConnectionAck})
	err = UDPSendMessage(udpConn, raddr, Message{Type: ConnectionAck})
	if err != nil {
		fmt.Println("send message error", err)
		return
	}
	for {
		msg, addr, err := UDPReceiveMessage(udpConn, time.Second*3)
		if err != nil {
			fmt.Println("receive message error", err)
			return
		}
		if msg.Type == ConnectionAck {
			endInfo := TraversalInfo{
				Laddr: lAddr.String(),
				Raddr: addr.String(),
			}
			infoChan <- endInfo
			return
		}
	}
}

func (t *TraversalTool) passiveBothSymmetric_UDP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	t.Predictor.NextPort()
	t.Predictor.NextPort()
	lAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	if InSameNat {
		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
		for i := 0; i < 22; i++ {
			t.Predictor.NextPort()
		}
	}
	go func() {
		for i := 0; i < 20; i++ {
			//打20个洞洞然后等待对方连接
			newAddr := rIP + ":" + t.Predictor.NextPort()
			fmt.Println("send to newAddr", newAddr)
			UDPSendMessage(udpConn, newAddr, Message{Type: Empty})
			err := UDPSendMessage(udpConn, newAddr, Message{Type: Empty})
			if err != nil {
				fmt.Println("send message error", err)
				continue
			}
		}
	}()
	for {
		msg, addr, err := UDPReceiveMessage(udpConn, time.Second*3)
		if err != nil {
			fmt.Println("receive message error", err)
			return TraversalInfo{}, err
		}
		fmt.Println("receive message", msg, addr)
		if msg.Type == ConnectionAck {
			UDPSendMessage(udpConn, addr.String(), Message{Type: ConnectionAck})
			UDPSendMessage(udpConn, addr.String(), Message{Type: ConnectionAck})
			err := UDPSendMessage(udpConn, addr.String(), Message{Type: ConnectionAck})
			if err != nil {
				fmt.Println("send message error", err)
			}
			endInfo := TraversalInfo{
				Laddr:     udpConn.LocalAddr().String(),
				Raddr:     addr.String(),
				LocalNat:  t.NATInfo,
				RemoteNat: rNAT,
			}
			return endInfo, nil
		}
	}
}

func (t *TraversalTool) beginTestNatType(udpConn *net.UDPConn) (NATTypeINfo, error) {
	for {
		msg, _, err := UDPReceiveMessage(udpConn, time.Second*2)
		if err != nil {
			return NATTypeINfo{}, fmt.Errorf("receive message error %w", err)
		}
		switch msg.Type {
		case PortNegotiation: //端口协商，向改变的端口发送消息，若服务器收到的地址端口改变，则说明是Symmetric NAT
			err := t.handlePortNegotiation(udpConn, msg)
			if err != nil {
				return NATTypeINfo{}, err
			}
			err = t.ProtocolChangeTest(udpConn)
			if err != nil {
				return NATTypeINfo{}, err
			}
		case ACK: //服务器确认收到消息
			// log.Println("receive ack from", raddr.String())
		case EndResult: //服务器确认NAT类型发回最终结果
			t.handleEndResult(msg)
			return t.NATInfo, nil //结束
		case ErrorResponse: //服务器返回错误信息
			return NATTypeINfo{}, fmt.Errorf("error response %s", msg.ErrorInfo)
		case ServerPortChangeTest: //服务器端口改变测试
			err := t.handleServerPortChangeTest(udpConn)
			if err != nil {
				return NATTypeINfo{}, err
			}
		default:
			return NATTypeINfo{}, fmt.Errorf("unknown message type %d", msg.Type)
		}
	}
}

func (t *TraversalTool) activeBothSymmetric_TCP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	t.Predictor.NextPort()
	t.Predictor.NextPort()
	for i := 0; i < 9; i++ {
		t.Predictor.NextPort()
	}
	newRport := t.Predictor.NextPort()
	fmt.Println("newRport", newRport)
	newRaddr := rIP + ":" + newRport
	fmt.Println("newRaddr", newRaddr)
	randPort := rand.Intn(20000) + 10000
	fmt.Println("rand port:", randPort)
	infoChan := make(chan TraversalInfo, 1)
	if InSameNat {
		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
		time.Sleep(time.Second)
	}
	for i := 0; i < 10; i++ {
		go SymmetricDail_TCP(newRaddr, randPort, infoChan)
		randPort++
	}
	for i := 0; i < 9; i++ {
		t.Predictor.NextPort()
	}
	newRport = t.Predictor.NextPort()
	fmt.Println("newRport", newRport)
	newRaddr = rIP + ":" + newRport
	fmt.Println("newRaddr", newRaddr)
	for i := 0; i < 10; i++ {
		go SymmetricDail_TCP(newRaddr, randPort, infoChan)
		randPort++
	}
	select {
	case endInfo := <-infoChan:
		endInfo.LocalNat = t.NATInfo
		endInfo.RemoteNat = rNAT
		return endInfo, nil
	case <-time.After(time.Second * 3):
		return TraversalInfo{}, fmt.Errorf("hole punching failed, no response")
	}
}

func SymmetricDail_TCP(raddr string, lport int, infoChan chan TraversalInfo) {
	lAddr, err := net.ResolveTCPAddr("tcp4", ":"+fmt.Sprint(lport))
	if err != nil {
		fmt.Println(err)
		return
	}
	rAddr, err := net.ResolveTCPAddr("tcp4", raddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	tcpConn, err := net.DialTCP("tcp4", lAddr, rAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tcpConn.LocalAddr().String())
	//成功建立连接
	endInfo := TraversalInfo{
		Laddr:   tcpConn.LocalAddr().String(),
		Raddr:   tcpConn.RemoteAddr().String(),
		TCPConn: tcpConn,
	}
	fmt.Println("endInfo", endInfo)
	select {
	case infoChan <- endInfo:
	default:
	}
}

func (t *TraversalTool) passiveBothSymmetric_TCP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT can not be predicted")
	}
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)
	t.Predictor.NextPort()
	t.Predictor.NextPort()
	if InSameNat {
		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
		for i := 0; i < 22; i++ {
			t.Predictor.NextPort()
		}
	}
	go func() {
		for i := 0; i < 20; i++ {
			//目的是打洞不是建立连接
			newAddr := rIP + ":" + t.Predictor.NextPort()
			go reuse.Dial("tcp4", laddr, newAddr)
		}
	}()
	Listener, err := reuse.Listen("tcp4", laddr)
	if err != nil {
		fmt.Println("listen tcp error", err)
		return TraversalInfo{}, err
	}
	tcpListener := Listener.(*net.TCPListener)
	tcpListener.SetDeadline(time.Now().Add(time.Second * 3))

	conn, err := tcpListener.AcceptTCP()
	if err != nil {
		fmt.Println("accept tcp error", err)
		return TraversalInfo{}, err
	}
	fmt.Println("accept tcp", conn.RemoteAddr().String())
	endInfo := TraversalInfo{
		Laddr:   conn.LocalAddr().String(),
		Raddr:   conn.RemoteAddr().String(),
		TCPConn: conn,
	}
	return endInfo, nil
}

func (t *TraversalTool) ProtocolChangeTest(udpConn *net.UDPConn) error {
	laddr, err := net.ResolveTCPAddr("tcp4", udpConn.LocalAddr().String())
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

func (t *TraversalTool) handleServerPortChangeTest(udpConn *net.UDPConn) error {
	msg := Message{
		Type:          ServerPortChangeTestResponse,
		IdentityToken: t.identityToken,
	}
	err := UDPSendMessage(udpConn, t.ServerAddr, msg)
	if err != nil {
		return fmt.Errorf("send message error %w", err)
	}
	return nil
}

func (t *TraversalTool) handlePortNegotiation(udpConn *net.UDPConn, msg Message) error {
	var port = string(msg.Data)
	tempAddr := t.ServerAddr[:strings.LastIndex(t.ServerAddr, ":")+1] + port
	fmt.Println("temp addr", tempAddr)
	msg = Message{
		Type:          PortNegotiationResponse,
		IdentityToken: t.identityToken,
	}
	err := UDPSendMessage(udpConn, tempAddr, msg)
	if err != nil {
		log.Println("send message error", err)
		return err
	}
	fmt.Println("send port negotiation response")
	return nil
}

func (t *TraversalTool) handleEndResult(msg Message) {
	if msg.ErrorInfo != "" {
		log.Println("error response", msg.ErrorInfo)
		return
	}
	var err error
	var natInfo NATTypeINfo
	err = json.Unmarshal(msg.Data, &natInfo)
	if err != nil {
		log.Println("unmarshal nat info error", err)
		return
	}
	t.NATInfo = natInfo
}
