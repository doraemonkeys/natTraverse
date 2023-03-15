package natTraverse

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Doraemonkeys/reliableUDP"
)

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
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
	defer rudpConn.Close()
	//这两个UDP的信息仅仅负责打洞，然后等待对方的连接
	RUDPSendUnreliableMessage(rudpConn, raddr, emptyMsg)
	err = RUDPSendUnreliableMessage(rudpConn, raddr, emptyMsg)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn.SetGlobalReceive()
	for {
		msg, newAddr, err := RUDPReceiveAllMessage(rudpConn, t.UDPTimeout)
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
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
	defer rudpConn.Close()
	mag := Message{Type: ConnectionAck}
	err = RUDPSendMessage(rudpConn, raddr, mag, t.UDPTimeout)
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

// 被动端，对方是对称NAT，打洞完成后，等待对方的连接
func (t *TraversalTool) portRestrictToSymmetric_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
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
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
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
		msg, addr, err := RUDPReceiveAllMessage(rudpConn, t.UDPTimeout)
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

func (t *TraversalTool) symmetricToPortRestrict_UDP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	LAddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	udpConn, err := net.ListenUDP("udp4", LAddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	rudpConn := reliableUDP.NewReliableUDP(udpConn)
	defer rudpConn.Close()
	rudpConn.SetGlobalReceive()
	for i := 0; i < 3; i++ {
		err := RUDPSendMessage(rudpConn, raddr, Message{Type: ConnectionAck}, t.UDPTimeout)
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
		return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
	}
	fmt.Println("activeBothSymmetric_UDP")
	rPort := strings.Split(raddr, ":")[1]
	rIP := strings.Split(raddr, ":")[0]
	fmt.Println("rPort", rPort)
	t.Predictor.SetInitialPort(rPort)

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
	time.Sleep(time.Second)
	for i := 0; i < 10; i++ {
		fmt.Println("dial newRaddr", newRaddr, "randPort", randPort)
		go SymmetricDail(newRaddr, randPort, infoChan, t.UDPTimeout)
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
		go SymmetricDail(newRaddr, randPort, infoChan, t.UDPTimeout)
		randPort++
	}
	select {
	case endInfo := <-infoChan:
		endInfo.LocalNat = t.NATInfo
		endInfo.RemoteNat = rNAT
		return endInfo, nil
	case <-time.After(t.UDPTimeout):
		return TraversalInfo{}, fmt.Errorf("hole punching failed, no response")
	}
}

func SymmetricDail(raddr string, lport int, infoChan chan TraversalInfo, timeout time.Duration) {
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
	UDPSendMessage(udpConn, raddr, Message{Type: ConnectionAck})
	err = UDPSendMessage(udpConn, raddr, Message{Type: ConnectionAck})
	if err != nil {
		fmt.Println("send message error", err)
		return
	}
	for {
		msg, addr, err := UDPReceiveMessage(udpConn, timeout)
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
		fmt.Println("success receive message", msg, "from", addr)
	}
}

func (t *TraversalTool) passiveBothSymmetric_UDP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
	if t.Predictor == nil {
		return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
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
		msg, addr, err := UDPReceiveMessage(udpConn, t.UDPTimeout)
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
