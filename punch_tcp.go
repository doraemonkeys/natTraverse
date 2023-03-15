package natTraverse

import (
	"fmt"
	"net"
)

// func (t *TraversalTool) activeBothSymmetric_TCP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
// 	if t.Predictor == nil {
// 		return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
// 	}
// 	rPort := strings.Split(raddr, ":")[1]
// 	rIP := strings.Split(raddr, ":")[0]
// 	fmt.Println("rPort", rPort)
// 	t.Predictor.SetInitialPort(rPort)
// 	for i := 0; i < 9; i++ {
// 		t.Predictor.NextPort()
// 	}
// 	newRport := t.Predictor.NextPort()
// 	fmt.Println("newRport", newRport)
// 	newRaddr := rIP + ":" + newRport
// 	fmt.Println("newRaddr", newRaddr)
// 	randPort := rand.Intn(20000) + 10000
// 	fmt.Println("rand port:", randPort)
// 	infoChan := make(chan TraversalInfo, 1)
// 	if InSameNat {
// 		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
// 		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
// 		time.Sleep(time.Second)
// 	}
// 	for i := 0; i < 10; i++ {
// 		go SymmetricDail_TCP(newRaddr, randPort, infoChan)
// 		randPort++
// 	}
// 	for i := 0; i < 9; i++ {
// 		t.Predictor.NextPort()
// 	}
// 	newRport = t.Predictor.NextPort()
// 	fmt.Println("newRport", newRport)
// 	newRaddr = rIP + ":" + newRport
// 	fmt.Println("newRaddr", newRaddr)
// 	for i := 0; i < 10; i++ {
// 		go SymmetricDail_TCP(newRaddr, randPort, infoChan)
// 		randPort++
// 	}
// 	select {
// 	case endInfo := <-infoChan:
// 		endInfo.LocalNat = t.NATInfo
// 		endInfo.RemoteNat = rNAT
// 		return endInfo, nil
// 	case <-time.After(time.Second * 3):
// 		return TraversalInfo{}, fmt.Errorf("hole punching failed, no response")
// 	}
// }

// func SymmetricDail_TCP(raddr string, lport int, infoChan chan TraversalInfo) {
// 	lAddr, err := net.ResolveTCPAddr("tcp4", ":"+fmt.Sprint(lport))
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	rAddr, err := net.ResolveTCPAddr("tcp4", raddr)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	tcpConn, err := net.DialTCP("tcp4", lAddr, rAddr)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	fmt.Println(tcpConn.LocalAddr().String())
// 	//成功建立连接
// 	endInfo := TraversalInfo{
// 		Laddr:   tcpConn.LocalAddr().String(),
// 		Raddr:   tcpConn.RemoteAddr().String(),
// 		TCPConn: tcpConn,
// 	}
// 	fmt.Println("endInfo", endInfo)
// 	select {
// 	case infoChan <- endInfo:
// 	default:
// 	}
// }

// func (t *TraversalTool) passiveBothSymmetric_TCP(laddr string, raddr string, InSameNat bool, rNAT NATTypeINfo) (TraversalInfo, error) {
// 	if t.Predictor == nil {
// 		return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
// 	}
// 	rPort := strings.Split(raddr, ":")[1]
// 	rIP := strings.Split(raddr, ":")[0]
// 	fmt.Println("rPort", rPort)
// 	t.Predictor.SetInitialPort(rPort)

// 	if InSameNat {
// 		//UDP打洞处于同一nat，被动等待的打洞方将预测对方的端口+22
// 		//主动连接的一方先暂停1s，确保前20个端口分配给了对方，然后其余保存不变
// 		for i := 0; i < 22; i++ {
// 			t.Predictor.NextPort()
// 		}
// 	}
// 	go func() {
// 		for i := 0; i < 20; i++ {
// 			//目的是打洞不是建立连接
// 			newAddr := rIP + ":" + t.Predictor.NextPort()
// 			go reuse.Dial("tcp4", laddr, newAddr)
// 		}
// 	}()
// 	Listener, err := reuse.Listen("tcp4", laddr)
// 	if err != nil {
// 		fmt.Println("listen tcp error", err)
// 		return TraversalInfo{}, err
// 	}
// 	tcpListener := Listener.(*net.TCPListener)
// 	tcpListener.SetDeadline(time.Now().Add(t.TCPTimeout))

// 	conn, err := tcpListener.AcceptTCP()
// 	if err != nil {
// 		fmt.Println("accept tcp error", err)
// 		return TraversalInfo{}, err
// 	}
// 	fmt.Println("accept tcp", conn.RemoteAddr().String())
// 	endInfo := TraversalInfo{
// 		Laddr:   conn.LocalAddr().String(),
// 		Raddr:   conn.RemoteAddr().String(),
// 		TCPConn: conn,
// 	}
// 	return endInfo, nil
// }

// func (t *TraversalTool) passiveBothNoSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
// 	//go  reuse.Dial("tcp4", laddr, raddr)
// 	go func() {
// 		c, err := reuse.Dial("tcp4", laddr, raddr) //打洞
// 		if err != nil {
// 			fmt.Println("expected dial error", err)
// 			return
// 		}
// 		//连接成功不会发生
// 		fmt.Println(c.LocalAddr().String(), "connect to", c.RemoteAddr().String())
// 	}()
// 	Listener, err := reuse.Listen("tcp4", laddr)
// 	if err != nil {
// 		fmt.Println("listen tcp error", err)
// 		return TraversalInfo{}, err
// 	}
// 	tcpListener := Listener.(*net.TCPListener)
// 	tcpListener.SetDeadline(time.Now().Add(t.TCPTimeout))
// 	defer tcpListener.Close()
// 	tcpConn, err := tcpListener.AcceptTCP()
// 	if err != nil {
// 		return TraversalInfo{}, err
// 	}
// 	endInfo := TraversalInfo{
// 		LocalNat:  t.NATInfo,
// 		RemoteNat: rNAT,
// 		Laddr:     laddr,
// 		Raddr:     raddr,
// 		TCPConn:   tcpConn,
// 	}
// 	return endInfo, nil
// }

func (t *TraversalTool) bothNoSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	//go  reuse.Dial("tcp4", laddr, raddr)
	// go func() {
	// 	c, err := reuse.Dial("tcp4", laddr, raddr) //打洞
	// 	if err != nil {
	// 		fmt.Println("expected dial error", err)
	// 		return
	// 	}
	// 	//连接成功不会发生
	// 	fmt.Println(c.LocalAddr().String(), "connect to", c.RemoteAddr().String())
	// }()
	// Listener, err := reuse.Listen("tcp4", laddr)
	// if err != nil {
	// 	fmt.Println("listen tcp error", err)
	// 	return TraversalInfo{}, err
	// }
	// tcpListener := Listener.(*net.TCPListener)
	// tcpListener.SetDeadline(time.Now().Add(t.TCPTimeout))
	// defer tcpListener.Close()
	// tcpConn, err := tcpListener.AcceptTCP()
	// if err != nil {
	// 	return TraversalInfo{}, err
	// }
	// endInfo := TraversalInfo{
	// 	LocalNat:  t.NATInfo,
	// 	RemoteNat: rNAT,
	// 	Laddr:     laddr,
	// 	Raddr:     raddr,
	// 	TCPConn:   tcpConn,
	// }
	// return endInfo, nil

	//tcp打洞直接互相dial就行了，不需要监听
	//Symmetric NAT暂时不支持
	Laddr, err := net.ResolveTCPAddr("tcp4", laddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	Raddr, err := net.ResolveTCPAddr("tcp4", raddr)
	if err != nil {
		return TraversalInfo{}, err
	}
	tcpConn, err := net.DialTCP("tcp4", Laddr, Raddr)
	if err != nil {
		//fmt.Println("try again")
		tcpConn, err = net.DialTCP("tcp4", Laddr, Raddr)
		if err != nil {
			return TraversalInfo{}, err
		}
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

// func (t *TraversalTool) activeBothNoSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
// 	// tcpConn, err := net.DialTimeout("tcp4", raddr, t.TCPTimeout)
// 	// if err != nil {
// 	// 	return TraversalInfo{}, err
// 	// }
// 	// endInfo := TraversalInfo{
// 	// 	LocalNat:  t.NATInfo,
// 	// 	RemoteNat: rNAT,
// 	// 	Laddr:     laddr,
// 	// 	Raddr:     raddr,
// 	// 	TCPConn:   tcpConn.(*net.TCPConn),
// 	// }
// 	conn, err := reuse.Dial("tcp4", laddr, raddr)
// 	if err != nil {
// 		return TraversalInfo{}, fmt.Errorf("final attempt to establish a TCP connection failed: %w", err)
// 	}
// 	endInfo := TraversalInfo{
// 		LocalNat:  t.NATInfo,
// 		RemoteNat: rNAT,
// 		Laddr:     laddr,
// 		Raddr:     raddr,
// 		TCPConn:   conn.(*net.TCPConn),
// 	}
// 	return endInfo, nil
// }

// 被动端，对方是对称NAT，打洞完成后，等待对方的连接
func (t *TraversalTool) portRestrictToSymmetric_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	// Not implemented yet

	// if t.Predictor == nil {
	// 	return TraversalInfo{}, fmt.Errorf("symmetric NAT with random ports is unpredictable")
	// }
	// rPort := strings.Split(raddr, ":")[1]
	// rIP := strings.Split(raddr, ":")[0]
	// fmt.Println("rPort", rPort)
	// t.Predictor.SetInitialPort(rPort)
	// go func() {
	// 	for i := 0; i < 20; i++ {
	// 		rPort := t.Predictor.NextPort()
	// 		new_rAddr := rIP + ":" + rPort
	// 		fmt.Println("new_rAddr", new_rAddr)
	// 		go reuse.Dial("tcp4", laddr, new_rAddr)
	// 	}
	// }()

	// Listener, err := reuse.Listen("tcp4", laddr)
	// if err != nil {
	// 	fmt.Println("listen tcp error", err)
	// 	return TraversalInfo{}, err
	// }
	// tcpListener := Listener.(*net.TCPListener)
	// tcpListener.SetDeadline(time.Now().Add(t.TCPTimeout))

	// conn, err := tcpListener.AcceptTCP()
	// if err != nil {
	// 	fmt.Println("final attempt to establish a TCP connection failed", err)
	// 	return TraversalInfo{}, err
	// }
	// fmt.Println("accept tcp", conn.RemoteAddr().String())
	// endInfo := TraversalInfo{
	// 	Laddr:     conn.LocalAddr().String(),
	// 	Raddr:     conn.RemoteAddr().String(),
	// 	LocalNat:  t.NATInfo,
	// 	RemoteNat: rNAT,
	// 	TCPConn:   conn,
	// }
	// return endInfo, nil
	return TraversalInfo{}, fmt.Errorf("not implemented yet")
}

func (t *TraversalTool) symmetricToPortRestrict_TCP(laddr string, raddr string, rNAT NATTypeINfo) (TraversalInfo, error) {
	// fmt.Println("dial tcp", laddr, raddr)
	// tcpConn, err := reuse.Dial("tcp4", laddr, raddr)
	// if err != nil {
	// 	return TraversalInfo{}, err
	// }
	// endInfo := TraversalInfo{
	// 	Laddr:     tcpConn.LocalAddr().String(),
	// 	Raddr:     tcpConn.RemoteAddr().String(),
	// 	LocalNat:  t.NATInfo,
	// 	RemoteNat: rNAT,
	// 	TCPConn:   tcpConn.(*net.TCPConn),
	// }
	// return endInfo, nil
	return TraversalInfo{}, fmt.Errorf("not implemented yet")
}
