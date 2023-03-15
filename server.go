package natTraverse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Doraemonkeys/reliableUDP"
)

func (t *TraversalServer) Run() {
	if t.testNATTimeout == 0 {
		t.testNATTimeout = 5 * time.Second
	}
	if t.recvTimeout == 0 {
		t.recvTimeout = 5 * time.Second
	}
	t.targetMap = make(map[string]chan Message)                //udp分发消息用
	t.tonkenMap = make(map[string]chan holePunchingConnection) //tcp找到两个想建立连接的节点
	TCPMsgCh := make(chan Message, 10)                         //TCP To UDP
	t.targetMapLock = &sync.Mutex{}
	t.tonkenMapLock = &sync.Mutex{}
	rand.Seed(time.Now().UnixNano())
	go t.testNATServer(TCPMsgCh)
	t.tCPListenServer(TCPMsgCh)
	// t.UDPListen()
	//time.Sleep(time.Second * 1000)
}

type holePunchingConnection struct {
	TCPConn *net.TCPConn
	NAT     NATTypeINfo
}

type nodeType int

const (
	passive nodeType = iota
	active
)

// 给两个想打洞的节点返回的消息
type holePunchingNegotiationMsg struct {
	MyPublicAddr string
	RPublicAddr  string
	RNAT         NATTypeINfo //对方的NAT类型
	ServerPort   string
	MyType       nodeType //主动还是被动
}

func (h *holePunchingNegotiationMsg) unmarshal(data []byte) error {
	return json.Unmarshal(data, h)
}

func (t *TraversalServer) tCPListenServer(TCPMsgCh chan Message) {
	TCPladdr, err := net.ResolveTCPAddr("tcp4", t.ListenAddr)
	if err != nil {
		log.Println("resolve tcp addr error", err)
		return
	}
	tcpListener, err := net.ListenTCP("tcp4", TCPladdr)
	if err != nil {
		log.Println("listen tcp error", err)
		return
	}
	defer tcpListener.Close()
	fmt.Println("tcp listen on", tcpListener.Addr().String())
	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			log.Println("accept tcp error", err)
			continue
		}
		go t.handleTCPConn(tcpConn, TCPMsgCh)
	}
}

func (t *TraversalServer) handleTCPConn(tcpConn *net.TCPConn, TCPMsgCh chan Message) {
	msg, err := TCPReceiveMessage(tcpConn)
	if err != nil {
		if err == io.EOF {
			log.Println(tcpConn.RemoteAddr().String(), "tcp connection closed")
		} else {
			log.Println("tcp receive message error", err)
		}
		tcpConn.Close()
		return
	}
	msg.SrcPublicAddr = tcpConn.RemoteAddr().String()
	fmt.Println("handleTCPConn receive message:", tcpConn.RemoteAddr().String())

	switch msg.Type {
	case ProtocolChangeTest:
		TCPMsgCh <- msg //TCP To UDP
		fmt.Println("message send to UDP", msg)
	case Connection:
		err := t.handleConnection(tcpConn, msg)
		if err != nil {
			log.Println("handle connection error", err)
		}
		return
	default:
		log.Println("unknown message type", msg.Type)
	}
	tcpConn.Close()
}

func (t *TraversalServer) handleConnection(tcpConn *net.TCPConn, msg Message) error {
	//根据IdentityToken判断对方请求的打洞类型
	if len(msg.IdentityToken) < 3 || (msg.IdentityToken[len(msg.IdentityToken)-3:] != "UDP" && msg.IdentityToken[len(msg.IdentityToken)-3:] != "TCP") {
		info := "identity token error,not found holepunching type"
		log.Println(info)
		err := TCPSendMessage(tcpConn, Message{Type: ErrorResponse, ErrorInfo: info})
		if err != nil {
			log.Println("send error response error", err)
		}
		return fmt.Errorf(info)
	}
	fmt.Println("IdentityToken", msg.IdentityToken)
	var natInfo NATTypeINfo
	err := json.Unmarshal(msg.Data, &natInfo)
	if err != nil {
		info := "unmarshal nat info error"
		log.Println(info)
		err := TCPSendMessage(tcpConn, Message{Type: ErrorResponse, ErrorInfo: info})
		if err != nil {
			log.Println("send error response error", err)
		}
		return fmt.Errorf(info)
	}

	ch, ok := t.tonkenMap[msg.IdentityToken]
	if ok {
		fmt.Println("start send holePunchingConnection to channe")
		if len(ch) > 0 {
			fmt.Println("channel is full")
		}
		if ch == nil {
			fmt.Println("channel is nil")
		}
		ch <- holePunchingConnection{TCPConn: tcpConn, NAT: natInfo}
		fmt.Println("send holePunchingConnection to channe ok")
		return nil
	}
	var tcpConn2 *net.TCPConn
	t.tonkenMapLock.Lock()
	ch, ok = t.tonkenMap[msg.IdentityToken]
	if ok {
		ch <- holePunchingConnection{TCPConn: tcpConn, NAT: natInfo}
		t.tonkenMapLock.Unlock()
		return nil
	}
	t.tonkenMap[msg.IdentityToken] = make(chan holePunchingConnection, 1)
	t.tonkenMapLock.Unlock()
	ch = t.tonkenMap[msg.IdentityToken]
	defer func(token string) {
		t.tonkenMapLock.Lock()
		delete(t.tonkenMap, token)
		t.tonkenMapLock.Unlock()
	}(msg.IdentityToken)
	holeType := msg.IdentityToken[len(msg.IdentityToken)-3:]

	var hole holePunchingConnection
	fmt.Println("wait holepunching object:", tcpConn.RemoteAddr().String())
	select {
	case hole = <-ch:
		tcpConn2 = hole.TCPConn
		fmt.Println("holepunching object:", tcpConn.RemoteAddr().String(), tcpConn2.RemoteAddr().String())
	//最多等待打洞的对象30秒
	case <-time.After(time.Second * 30):
		info := "connection timeout,not found holepunching object"
		log.Println(info)
		err := TCPSendMessage(tcpConn, Message{Type: ErrorResponse, ErrorInfo: info})
		if err != nil {
			log.Println("send error response error", err)
		}
		return fmt.Errorf(info)
	}
	//检查tcpConn是否已经关闭
	msg = Message{Type: ACK}
	err = TCPSendMessage(tcpConn, msg)
	if err != nil {
		log.Println("send ack error", err)
		info := "remote connection closed"
		err := TCPSendMessage(tcpConn2, Message{Type: ErrorResponse, ErrorInfo: info})
		if err != nil {
			log.Println("send error response error", err)
		}
		return err
	}
	//检查tcpConn2是否已经关闭
	msg = Message{Type: ACK}
	err = TCPSendMessage(tcpConn2, msg)
	if err != nil {
		log.Println("send ack error", err)
		info := "remote connection closed"
		err := TCPSendMessage(tcpConn, Message{Type: ErrorResponse, ErrorInfo: info})
		if err != nil {
			log.Println("send error response error", err)
		}
		return err
	}

	if holeType == "UDP" {
		err := t.handleUDPHolePunching(tcpConn, tcpConn2, natInfo, hole.NAT)
		if err != nil {
			log.Println("handleUDPHolePunching error", err)
			return err
		}
		return nil
	}
	if holeType == "TCP" {
		err := handleTCPHolePunching(tcpConn, tcpConn2, natInfo, hole.NAT)
		if err != nil {
			log.Println("handleTCPHolePunching error", err)
			return err
		}
		return nil
	}
	return nil
}

func (t *TraversalServer) handleUDPHolePunching(tcpConn1, tcpConn2 *net.TCPConn, natInfo1, natInfo2 NATTypeINfo) error {
	//创建两个随机端口的UDP连接，用可靠UDP协议包装
	tempUdpConn1, err := UDPRandListen()
	if err != nil {
		log.Println("listen udp error", err)
		return err
	}
	tempRudpConn1 := reliableUDP.NewReliableUDP(tempUdpConn1)
	tempRudpConn1.SetGlobalReceive()

	tempUdpConn2, err := UDPRandListen()
	if err != nil {
		log.Println("listen udp error", err)
		return err
	}
	tempRudpConn2 := reliableUDP.NewReliableUDP(tempUdpConn2)
	tempRudpConn2.SetGlobalReceive()

	randPort1 := tempUdpConn1.LocalAddr().(*net.UDPAddr).Port
	randPort2 := tempUdpConn2.LocalAddr().(*net.UDPAddr).Port
	//虽说是端口，但是这里是一个字符串，包含了ip和端口
	portCh1 := make(chan string, 1)
	portCh2 := make(chan string, 1)
	go func() {
		_, addr, err := RUDPReceiveAllMessage(tempRudpConn1, t.recvTimeout)
		if err != nil {
			log.Println("receive message error", err)
			return
		}
		portCh1 <- addr.String() //虽说是端口，但是这里是一个字符串，包含了ip和端口
		tempRudpConn1.Close()
	}()
	go func() {
		_, addr, err := RUDPReceiveAllMessage(tempRudpConn2, t.recvTimeout)
		if err != nil {
			log.Println("receive message error", err)
			return
		}
		portCh2 <- addr.String()
		tempRudpConn2.Close()
	}()
	//设置两个节点谁主动谁被动
	var conn1Isactive bool
	if natInfo1.NATType != Symmetric && natInfo2.NATType == Symmetric {
		//PortRestrict To Symmetric
		conn1Isactive = false
	} else {
		conn1Isactive = true
	}
	//通知两个节点向我发送udp消息以此获取结点的公网端口
	msg1 := Message{
		Type: PunchingNegotiation,
	}
	holeMsg1 := holePunchingNegotiationMsg{
		MyPublicAddr: tcpConn1.RemoteAddr().String(),
		RPublicAddr:  tcpConn2.RemoteAddr().String(),
		RNAT:         natInfo2,
		ServerPort:   fmt.Sprintf("%d", randPort1),
	}
	if conn1Isactive {
		holeMsg1.MyType = active
	} else {
		holeMsg1.MyType = passive
	}
	data1, err := json.Marshal(holeMsg1)
	if err != nil {
		log.Println("marshal holepunching negotiation message error", err)
		return err
	}
	msg1.Data = data1

	// err = TCPSendMessage(tcpConn1, msg1)
	// if err != nil {
	// 	log.Println("send port negotiation message error", err)
	// 	return err
	// }
	msg2 := Message{
		Type: PunchingNegotiation,
	}
	holeMsg2 := holePunchingNegotiationMsg{
		MyPublicAddr: tcpConn2.RemoteAddr().String(),
		RPublicAddr:  tcpConn1.RemoteAddr().String(),
		RNAT:         natInfo1,
		ServerPort:   fmt.Sprintf("%d", randPort2),
	}
	if conn1Isactive {
		holeMsg2.MyType = passive
	} else {
		holeMsg2.MyType = active
	}
	data2, err := json.Marshal(holeMsg2)
	if err != nil {
		log.Println("marshal holepunching negotiation message error", err)
		return err
	}
	msg2.Data = data2
	//发送打洞协商消息,被动方先发
	//先给打洞方(被动方)发端口信息，防止洞还没打好连接请求就到了
	if conn1Isactive {
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	} else {
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	}
	log.Println("send port negotiation message success")
	//等待两个节点的端口信息
	var newRaddr1, newRaddr2 string
	for {
		select {
		case newRaddr1 = <-portCh1:
			log.Println("receive port1", newRaddr1)
		case newRaddr2 = <-portCh2:
			log.Println("receive port2", newRaddr2)
		case <-time.After(5 * time.Second): //时间间隔太长两个peer节点的端口就不具有时效性了
			err := errors.New("receive port timeout")
			log.Println(err)
			errMsg := Message{
				Type:      ErrorResponse,
				ErrorInfo: err.Error(),
			}
			TCPSendMessage(tcpConn1, errMsg)
			TCPSendMessage(tcpConn2, errMsg)
			return err
		}
		if newRaddr1 != "" && newRaddr2 != "" {
			break
		}
	}
	//通知两个节点对方的公网地址和端口，开始打洞
	msg1 = Message{
		Type: StartPunching,
		Data: []byte(newRaddr2),
	}
	msg2 = Message{
		Type: StartPunching,
		Data: []byte(newRaddr1),
	}
	if conn1Isactive {
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	} else {
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	}
	return nil
}

func handleTCPHolePunching(tcpConn1, tcpConn2 *net.TCPConn, natInfo1, natInfo2 NATTypeINfo) error {
	//创建两个随机端口的TCP监听
	tempTCPListener1, err := TCPRandListen()
	if err != nil {
		log.Println("create temp tcp listener error", err)
		return err
	}
	defer tempTCPListener1.Close()
	tempTCPListener2, err := TCPRandListen()
	if err != nil {
		log.Println("create temp tcp listener error", err)
		return err
	}
	defer tempTCPListener2.Close()
	randPort1 := tempTCPListener1.Addr().(*net.TCPAddr).Port
	randPort2 := tempTCPListener2.Addr().(*net.TCPAddr).Port
	//虽说是端口，但是这里是一个字符串，包含了ip和端口
	portCh1 := make(chan string, 1)
	portCh2 := make(chan string, 1)
	go func() {
		tcpConn, err := tempTCPListener1.AcceptTCP()
		if err != nil {
			log.Println("accept tcp connection error", err)
			return
		}
		portCh1 <- tcpConn.RemoteAddr().String()
		tcpConn.Close()
	}()
	go func() {
		tcpConn, err := tempTCPListener2.AcceptTCP()
		if err != nil {
			log.Println("accept tcp connection error", err)
			return
		}
		portCh2 <- tcpConn.RemoteAddr().String()
		tcpConn.Close()
	}()
	//设置两个节点谁主动谁被动
	var conn1IsActive bool
	if natInfo1.NATType != Symmetric && natInfo2.NATType == Symmetric {
		//PortRestrictToSymmetric_TCP
		conn1IsActive = false
	} else {
		conn1IsActive = true
	}
	//通知两个节点向我连接tcp以此获取结点的公网端口
	msg1 := Message{
		Type: PunchingNegotiation,
	}
	holeMsg1 := holePunchingNegotiationMsg{
		MyPublicAddr: tcpConn1.RemoteAddr().String(),
		RPublicAddr:  tcpConn2.RemoteAddr().String(),
		RNAT:         natInfo2,
		ServerPort:   fmt.Sprintf("%d", randPort1),
	}
	if conn1IsActive {
		holeMsg1.MyType = active
	} else {
		holeMsg1.MyType = passive
	}
	data1, err := json.Marshal(holeMsg1)
	if err != nil {
		log.Println("marshal hole punching negotiation message error", err)
		return err
	}
	msg1.Data = data1

	msg2 := Message{
		Type: PunchingNegotiation,
	}
	holeMsg2 := holePunchingNegotiationMsg{
		MyPublicAddr: tcpConn2.RemoteAddr().String(),
		RPublicAddr:  tcpConn1.RemoteAddr().String(),
		RNAT:         natInfo1,
		ServerPort:   fmt.Sprintf("%d", randPort2),
	}
	if conn1IsActive {
		holeMsg2.MyType = passive
	} else {
		holeMsg2.MyType = active
	}
	data2, err := json.Marshal(holeMsg2)
	if err != nil {
		log.Println("marshal hole punching negotiation message error", err)
		return err
	}
	msg2.Data = data2
	//发送打洞协商消息,被动方先发
	//先给打洞方(被动方)发端口信息，防止洞还没打好连接请求就到了
	if conn1IsActive {
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	} else {
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	}
	//等待两个节点的端口信息
	var newRaddr1, newRaddr2 string
	for {
		select {
		case newRaddr1 = <-portCh1:
			log.Println("receive port1", newRaddr1)
		case newRaddr2 = <-portCh2:
			log.Println("receive port2", newRaddr2)
		case <-time.After(5 * time.Second): //时间间隔太长两个peer节点的端口就不具有时效性了
			log.Println("receive port timeout")
			return errors.New("receive port timeout")
		}
		if newRaddr1 != "" && newRaddr2 != "" {
			break
		}
	}
	if newRaddr1[:strings.LastIndex(newRaddr1, ":")] != tcpConn1.RemoteAddr().String()[:strings.LastIndex(tcpConn1.RemoteAddr().String(), ":")] {
		log.Println("receive port1 error")
		fmt.Println(newRaddr1[:strings.LastIndex(newRaddr1, ":")], tcpConn1.RemoteAddr().String()[:strings.LastIndex(tcpConn1.RemoteAddr().String(), ":")])
		return errors.New("receive port1 error")
	}
	if newRaddr2[:strings.LastIndex(newRaddr2, ":")] != tcpConn2.RemoteAddr().String()[:strings.LastIndex(tcpConn2.RemoteAddr().String(), ":")] {
		log.Println("receive port2 error")
		fmt.Println(newRaddr2[:strings.LastIndex(newRaddr2, ":")], tcpConn2.RemoteAddr().String()[:strings.LastIndex(tcpConn2.RemoteAddr().String(), ":")])
		return errors.New("receive port2 error")
	}
	//通知两个节点对方的公网地址和端口，开始打洞
	msg1 = Message{
		Type: StartPunching,
		Data: []byte(newRaddr2),
	}
	msg2 = Message{
		Type: StartPunching,
		Data: []byte(newRaddr1),
	}
	if conn1IsActive {
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	} else {
		err = TCPSendMessage(tcpConn1, msg1)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
		err = TCPSendMessage(tcpConn2, msg2)
		if err != nil {
			log.Println("send port negotiation message error", err)
			return err
		}
	}
	return nil
}

func (t *TraversalServer) testNATServer(TCPMsgCh chan Message) {
	laddr, err := net.ResolveUDPAddr("udp4", t.ListenAddr)
	if err != nil {
		panic(err)
	}
	udpConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		panic(err)
	}
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
	defer rudpConn.Close()
	rudpConn.SetGlobalReceive()
	var msg Message
	receiveCh := make(chan Message, 1)
	go func() {
		for {
			msg, raddr, err := RUDPReceiveAllMessage(rudpConn, 0)
			if err != nil {
				log.Println("test nat server receive message error", err)
				continue
			}
			msg.SrcPublicAddr = raddr.String()
			receiveCh <- msg
		}
	}()
	for {
		select {
		case msg = <-receiveCh:
		case msg = <-TCPMsgCh:
		}
		fmt.Println("TestNATServer receive message:", msg.Type, msg.IdentityToken, string(msg.Data))
		switch msg.Type {
		case TestNatType:
			_, ok := t.targetMap[msg.IdentityToken]
			if ok {
				log.Println("receive duplicate message,identityToken:", msg.IdentityToken)
				continue
			}
			ch := make(chan Message, 2)
			t.targetMapLock.Lock()
			t.targetMap[msg.IdentityToken] = ch
			t.targetMapLock.Unlock()
			go t.handleTestNatType(rudpConn, msg.SrcPublicAddr, msg.IdentityToken, ch)
		default:
			ch := t.targetMap[msg.IdentityToken]
			if ch != nil {
				ch <- msg
			} else {
				log.Println("receive timeout message:", msg.Type, msg.IdentityToken, string(msg.Data))
			}
		}
	}
}

func (t *TraversalServer) handleTestNatType(rudpConn *reliableUDP.ReliableUDP, raddr string, identityToken string, UDPMsgCh chan Message) {
	defer func() {
		t.targetMapLock.Lock()
		delete(t.targetMap, identityToken)
		t.targetMapLock.Unlock()
	}()
	var msg Message
	msg.Type = ACK
	err := RUDPSendMessage(rudpConn, raddr, msg, t.testNATTimeout)
	if err != nil {
		log.Println("send message error", err)
		return
	}
	fmt.Println("send ack to", raddr)
	//随机监听一个端口，等待对方连接，看看公网端口是否变化
	tempUDPConn, err := UDPRandListen()
	if err != nil {
		log.Println("listen udp error", err)
		return
	}
	tempRUdpConn := reliableUDP.NewReliableUDP(tempUDPConn)
	defer tempRUdpConn.Close()
	//defer tempUdpConn.Close()
	randPort := tempRUdpConn.LocalAddr().String()[strings.LastIndex(tempRUdpConn.LocalAddr().String(), ":")+1:]
	fmt.Println("rand port:", randPort)
	msg.Type = PortNegotiation
	msg.Data = []byte(fmt.Sprint(randPort))
	//fmt.Println("send port negotiation,data:", string(msg.Data))
	err = RUDPSendMessage(rudpConn, raddr, msg, t.testNATTimeout)
	if err != nil {
		log.Println("send message error", err)
		return
	}
	fmt.Println("send port negotiation to", raddr)
	tempRUdpConn.SetGlobalReceive()
	msg, newRAddr, err := RUDPReceiveAllMessage(tempRUdpConn, t.testNATTimeout)
	if err != nil {
		log.Println("receive message error", err)
		return
	}
	fmt.Println("receive message from", newRAddr.String())
	if msg.Type != PortNegotiationResponse {
		log.Println("receive message error", msg.Type, msg.IdentityToken, string(msg.Data))
		return
	}
	natInfo := NATTypeINfo{}
	FinallType := UnKnown
	var changeRule PortChange
	if newRAddr.String() != raddr {
		//Symmetric NAT
		log.Println("Symmetric NAT")
		FinallType = Symmetric
		raddrPort, err := strconv.Atoi(raddr[strings.LastIndex(raddr, ":")+1:])
		if err != nil {
			log.Println("strconv.Atoi error", err)
			return
		}
		//端口变化范围
		portRange := math.Abs(float64(raddrPort - newRAddr.Port))
		if portRange <= 100 {
			changeRule = Linear
		} else {
			changeRule = UnKnownRule
		}
	} else {
		//非对称NAT
		tempUDPConn, err := UDPRandListen()
		if err != nil {
			log.Println("listen udp error", err)
			return
		}
		tempRUdpConn := reliableUDP.NewReliableUDP(tempUDPConn)
		defer tempRUdpConn.Close()
		msg2 := Message{
			Type: ServerPortChangeTest,
		}
		RUDPSendUnreliableMessage(tempRUdpConn, raddr, msg2)
		err = RUDPSendUnreliableMessage(tempRUdpConn, raddr, msg2)
		if err != nil {
			log.Println("send message error", err)
			return
		}
		fmt.Println("send server port change test to", raddr)
		var tempMsg Message
		var ok bool = true
		for ok {
			select {
			case msg = <-UDPMsgCh:
				log.Println("receive message", msg.Type, msg.IdentityToken, string(msg.Data))
				if msg.Type == ServerPortChangeTestResponse {
					FinallType = FullOrRestrictedCone
				} else if msg.Type == ProtocolChangeTest {
					tempMsg = msg
				} else {
					log.Println("unexpected message", msg.Type, msg.IdentityToken, string(msg.Data))
				}
			case <-time.After(time.Second * 2):
				//大部分情况不接受来自同一IP不同端口的访问请求，即PortRestrictedCone
				//所以这里的超时时间不能太长
				log.Println("receive message timeout")
				FinallType = PortRestrictedCone
				if tempMsg.SrcPublicAddr != "" {
					UDPMsgCh <- tempMsg //读到了协议改变的消息，把消息放回去，下面处理(tcp传过来的)
				}
				ok = false
			}
		}
	}
	var ok bool = true
	for ok {
		select {
		case msg = <-UDPMsgCh:
			log.Println("receive message", msg.Type, msg.IdentityToken, string(msg.Data))
			if msg.Type == ServerPortChangeTestResponse {
				FinallType = FullOrRestrictedCone
			} else if msg.Type == ProtocolChangeTest {
				if raddr == msg.SrcPublicAddr {
					natInfo.PortInfluencedByProtocol = false
				} else {
					natInfo.PortInfluencedByProtocol = true
				}
				ok = false
			} else {
				log.Println("unexpected message", msg.Type, msg.IdentityToken, string(msg.Data))
			}
		case <-time.After(time.Second * 10):
			//正常情况下不会超时，一定会收到协议改变的消息(peer同一地址发送给服务器不同协议的消息)
			log.Println("receive message timeout,unexpected case")
			natInfo.PortInfluencedByProtocol = true
			ok = false
		}
	}
	natInfo.NATType = FinallType
	if FinallType == Symmetric {
		natInfo.UDPPortChangeRule = changeRule
	}
	data, err := json.Marshal(natInfo)
	if err != nil {
		log.Println("marshal nat info error", err)
		return
	}
	finnalMsg := Message{
		Type:          EndResult,
		IdentityToken: msg.IdentityToken,
		Data:          data,
	}
	fmt.Println("send end result", string(data))
	err = RUDPSendMessage(rudpConn, raddr, finnalMsg, t.testNATTimeout)
	if err != nil {
		log.Println("send message error", err)
		return
	}
	fmt.Println("send end result to", raddr)
}
