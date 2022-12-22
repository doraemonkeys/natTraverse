package natTraverse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

//注意事项
// 1.没有考虑序号溢出的情况
// 2.发送单个数据包最大为1024-8字节
// 3.50s后断开连接

type addrInfo struct {
	seq uint32 //发送序号，第几次发送，第一个序号为1
	//ack只在一个goroutine中修改，不需要加锁
	ack uint32 //确认号，ack-1为最后一次收到的序号,对对方的确认
	//myAck只在一个goroutine中修改，不需要加锁
	myAck           uint32      //自己的确认号，收到对方的ack包后，myAck=收到的ack-1，用于判断是否收到对方的ack包，最大为seq，最小为0
	lastActive      time.Time   //最后一次活跃时间
	connectionState bool        //连接状态，握手成功后为true，断开连接后为false
	waitConnection  bool        //我方正处于握手的状态
	randNum         uint32      //随机数，标识一次连接，用于防止对方过期的握手包
	seqLock         *sync.Mutex //发送序号的锁，保证每次发送的序号不一样
}

// 给全局消息通道用的结构体
type udpMsg struct {
	data []byte
	addr *net.UDPAddr
}

type ReliableUDP struct {
	conn         *net.UDPConn
	addrMap      map[string]*addrInfo   //string必须为ip:port
	mapLock      *sync.RWMutex          //两个Map的锁，保证读写安全
	dataMap      map[string]chan []byte //string必须为ip:port,用于不同地址的数据包缓冲
	close        bool                   //关闭标志
	receiveAllCh chan udpMsg            //接收所有数据包的通道
}

// 应该确保conn是可用的,且之后不能再使用conn
func NewReliableUDP(conn *net.UDPConn) *ReliableUDP {
	var rUDP = &ReliableUDP{
		conn:    conn,
		addrMap: make(map[string]*addrInfo),
		mapLock: &sync.RWMutex{},
		dataMap: make(map[string]chan []byte),
	}
	go rUDP.recv()
	//清除超时的addrInfo,超时时间为50s
	go rUDP.clearTimeoutAddrInfo()
	rand.Seed(time.Now().UnixNano())
	return rUDP
}

func (r *ReliableUDP) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

// 接收数据,返回ack
func (r *ReliableUDP) recv() {
	var data [1024]byte
	for {
		if r.close {
			return
		}
		n, addr, err := r.conn.ReadFromUDP(data[:]) //Close后会停止阻塞
		if err != nil {
			continue
		}
		r.mapLock.RLock()
		newAddrInfo, ok := r.addrMap[addr.String()]
		r.mapLock.RUnlock()
		if !ok {
			newAddrInfo = &addrInfo{ack: 1}
			r.mapLock.Lock()
			r.addrMap[addr.String()] = newAddrInfo
			r.dataMap[addr.String()] = make(chan []byte, 50) //缓冲区大小,超过50个数据包后会阻塞,所以应该尽快读取
			newAddrInfo.seqLock = &sync.Mutex{}
			r.mapLock.Unlock()
		}
		if n < 8 { //数据包最小为8字节
			continue
		}
		newAddrInfo.lastActive = time.Now()
		recvSeq := binary.LittleEndian.Uint32(data[:4])
		ack := binary.LittleEndian.Uint32(data[4:8])
		// seq ack
		// 0   >1 普通ack
		// 0   0  握手包，若不带随机数则为关闭连接包
		// 0   1  握手确认包
		// 1   0 不可靠的数据包
		// 1   1 是合法的数据包，表示我方还没发送数据，对方发送了第一个数据包
		if recvSeq == 0 && ack > 1 {
			//ack包
			if newAddrInfo.myAck < ack-1 {
				newAddrInfo.myAck = ack - 1
			}
			continue
		}
		if recvSeq == 0 && ack == 0 {
			//fmt.Println("握手包")
			if n < 12 {
				//关闭连接包
				//fmt.Println("关闭连接包")
				r.mapLock.Lock()
				delete(r.addrMap, addr.String())
				delete(r.dataMap, addr.String())
				r.mapLock.Unlock()
				continue
			}
			if newAddrInfo.randNum == binary.LittleEndian.Uint32(data[8:12]) {
				//过期的握手包
				//fmt.Println("过期的握手包")
				//fmt.Println(newAddrInfo.randNum, binary.LittleEndian.Uint32(data[8:12]))
				r.sendAck(1, addr) //重传握手确认包
				continue
			}
			newAddrInfo.seqLock.Lock()
			//我方处于握手状态，代表我已经准备好，此时又收到对方的握手包，说明对方也准备好了
			//此时我方随机数已经生成赋值给randNum，所以替换为对方的随机数(随机数用于防止对方过期的握手包)
			if newAddrInfo.waitConnection {
				//fmt.Println("我方处于握手状态，代表我已经准备好，此时又收到对方的握手包，说明对方也准备好了")
				newAddrInfo.randNum = binary.LittleEndian.Uint32(data[8:12])
				newAddrInfo.seqLock.Unlock()
				newAddrInfo.connectionState = true
				newAddrInfo.waitConnection = false
				continue
			} else {
				//fmt.Println("我方处于非握手状态")
				newAddrInfo.waitConnection = true
				newAddrInfo.seqLock.Unlock()
				go func() {
					time.Sleep(time.Second * 30)
					newAddrInfo.waitConnection = false
					//fmt.Println("等待握手超时")
				}()
			}
			newAddrInfo.randNum = binary.LittleEndian.Uint32(data[8:12])
			//握手包，这表示建立一个新的连接
			if newAddrInfo.seq != 0 {
				newAddrInfo.seqLock.Lock()
				//fmt.Println("seq重置")
				newAddrInfo.seq = 0
				newAddrInfo.seqLock.Unlock()
			}
			newAddrInfo.myAck = 0
			newAddrInfo.ack = 1
			//fmt.Printf("%#v\n", newAddrInfo)
			r.sendAck(1, addr) //发送握手确认包
			continue
		}
		if recvSeq == 0 && ack == 1 {
			//握手确认包，这表示连接建立成功
			newAddrInfo.connectionState = true
			newAddrInfo.waitConnection = false
			continue
		}
		if recvSeq == 1 && ack == 1 {
			//对方发送的第一个数据包,说明对方收到了我方的握手确认包，握手成功
			//fmt.Println("对方发送的第一个数据包,说明对方收到了我方的握手确认包")
			newAddrInfo.waitConnection = false
		}
		if recvSeq == 1 && ack == 0 {
			//对方发送的不可靠的数据包(不携带序号)
			if r.receiveAllCh != nil {
				r.receiveAllCh <- udpMsg{addr: addr, data: data[8:n]}
			} else {
				r.mapLock.RLock()
				r.dataMap[addr.String()] <- data[8:n]
				r.mapLock.RUnlock()
			}
			continue
		}
		if recvSeq < newAddrInfo.ack {
			//旧包,发送ack
			//fmt.Println("旧包", recvSeq, "ack", ack, "myAck", newAddrInfo.myAck, "addr", addr.String())
			r.sendAck(newAddrInfo.ack, addr)
			continue
		}
		if recvSeq != newAddrInfo.ack {
			//收到超前乱序的新包直接丢弃(不然处理太麻烦了)
			//fmt.Println("收到超前乱序的新包直接丢弃", recvSeq, "ack", ack, "myAck", newAddrInfo.myAck, "addr", addr.String())
			continue
		}
		//新包
		newAddrInfo.ack = recvSeq + 1
		//fmt.Println("接收到新包", recvSeq, "ack", ack, "myAck", newAddrInfo.myAck, "addr", addr.String())
		if r.receiveAllCh != nil {
			r.receiveAllCh <- udpMsg{addr: addr, data: data[8:n]}
		} else {
			r.mapLock.RLock()
			r.dataMap[addr.String()] <- data[8:n]
			r.mapLock.RUnlock()
		}
		//发送ack
		r.sendAck(newAddrInfo.ack, addr)
	}
}

func (r *ReliableUDP) sendAck(ack uint32, addr *net.UDPAddr) {
	var buf = new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint32(0))
	if err != nil {
		return
	}
	err = binary.Write(buf, binary.LittleEndian, ack)
	if err != nil {
		return
	}
	_, err = r.conn.WriteToUDP(buf.Bytes(), addr)
	if err != nil {
		return
	}
}

func (r *ReliableUDP) sendHandshake(randNum uint32, addr *net.UDPAddr) {
	var buf = new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint32(0))
	if err != nil {
		return
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(0))
	if err != nil {
		return
	}
	//fmt.Println("发送握手包", randNum, "addr", addr.String())
	err = binary.Write(buf, binary.LittleEndian, randNum)
	if err != nil {
		return
	}
	_, err = r.conn.WriteToUDP(buf.Bytes(), addr)
	if err != nil {
		return
	}
}

// 清除超时的addrInfo
func (r *ReliableUDP) clearTimeoutAddrInfo() {
	var tempMap1 = r.addrMap
	var tempMap2 = r.dataMap
	for {
		if r.close {
			return
		}
		time.Sleep(time.Second * 5)
		var delList []string
		r.mapLock.RLock()
		for k, v := range tempMap1 {
			if time.Since(v.lastActive) > time.Second*50 {
				delList = append(delList, k)
			}
		}
		r.mapLock.RUnlock()
		for _, v := range delList {
			r.mapLock.Lock()
			delete(tempMap1, v)
			delete(tempMap2, v)
			r.mapLock.Unlock()
		}
	}
}

// 最多发送1024-4字节,并发安全
func (r *ReliableUDP) Send(data []byte, addr *net.UDPAddr) error {
	r.mapLock.RLock()
	newAddrInfo, ok := r.addrMap[addr.String()]
	r.mapLock.RUnlock()
	if !ok {
		newAddrInfo = &addrInfo{ack: 1}
		r.mapLock.Lock()
		r.addrMap[addr.String()] = newAddrInfo
		r.dataMap[addr.String()] = make(chan []byte, 10) //接收缓冲区大小为10个数据包
		newAddrInfo.seqLock = &sync.Mutex{}
		r.mapLock.Unlock()
	}
	if newAddrInfo.seq == 0 && newAddrInfo.ack == 1 {
		newAddrInfo.seqLock.Lock()
		if !newAddrInfo.waitConnection {
			//表示第一次向对方发送数据，需要先握手
			//fmt.Println("第一次向对方发送数据，需要先握手", addr.String())
			newAddrInfo.waitConnection = true //设置为握手状态
			newAddrInfo.seqLock.Unlock()
			randNum := rand.Uint32()
			newAddrInfo.randNum = randNum
			count := 0
		loop:
			for {
				r.sendHandshake(randNum, addr)
				i := 0
				for i < 20 {
					if newAddrInfo.connectionState {
						//fmt.Println("握手成功", addr.String())
						break loop //握手成功,开始发送数据
					}
					time.Sleep(time.Millisecond * 10)
					i++
				}
				count++
				if count > 20 {
					return errors.New("handshake timeout")
				}
				//fmt.Println("握手超时，重发")
			}
		} else {
			newAddrInfo.seqLock.Unlock()
		}
	}
	for newAddrInfo.seq-newAddrInfo.myAck > 5 {
		//发送太多的数据包没用，会被对方丢弃，等待对方确认
		time.Sleep(time.Millisecond * 100)
	}
	var tempSeq uint32
	newAddrInfo.seqLock.Lock()
	newAddrInfo.seq++
	tempSeq = newAddrInfo.seq
	newAddrInfo.seqLock.Unlock()

	var buf = new(bytes.Buffer)
	//前8个字节为序号和确认号
	err := binary.Write(buf, binary.LittleEndian, tempSeq)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, newAddrInfo.ack)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	count := 0
	for {
		_, err = r.conn.WriteToUDP(buf.Bytes(), addr)
		if err != nil {
			return err
		}
		//等待ack
		i := 0
		for i < 20 {
			if newAddrInfo.myAck >= tempSeq {
				return nil
			}
			if newAddrInfo.seq == 0 {
				return errors.New("connection closed")
			}
			time.Sleep(10 * time.Millisecond)
			i++
		}
		count++
		if count > 20 {
			if newAddrInfo.seq != 0 {
				newAddrInfo.seqLock.Lock()
				newAddrInfo.seq--
				newAddrInfo.seqLock.Unlock()
			}
			return errors.New("send timeout")
		}
	}
}

// 不可靠的udp发送,并发安全
func (r *ReliableUDP) SendUnreliable(data []byte, addr *net.UDPAddr) error {
	var buf = new(bytes.Buffer)
	//前8个字节为序号和确认号
	err := binary.Write(buf, binary.LittleEndian, uint32(0))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(0))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	_, err = r.conn.WriteToUDP(buf.Bytes(), addr)
	if err != nil {
		return err
	}
	return nil
}

// 最多接收1024-4字节
func (r *ReliableUDP) Receive(addr *net.UDPAddr, timeout time.Duration) ([]byte, error) {
	r.mapLock.RLock()
	dataCH, ok := r.dataMap[addr.String()]
	r.mapLock.RUnlock()
	if !ok {
		r.mapLock.Lock()
		r.addrMap[addr.String()] = &addrInfo{ack: 1}
		r.dataMap[addr.String()] = make(chan []byte, 10) //接收缓冲区大小为10个数据包
		r.mapLock.Unlock()
		dataCH = r.dataMap[addr.String()]
	}
	if timeout == 0 {
		return <-dataCH, nil
	}
	select {
	case data := <-dataCH:
		return data, nil
	case <-time.After(timeout):
		return nil, errors.New(addr.String() + " receive timeout")
	}
}

// 取消全局接收
func (r *ReliableUDP) CancelGlobalReceive() {
	tempCh := r.receiveAllCh
	r.receiveAllCh = nil
	//清空通道，可能会导致乱序
	for v := range tempCh {
		r.mapLock.RLock()
		dataCH, ok := r.dataMap[v.addr.String()]
		r.mapLock.RUnlock()
		if ok {
			dataCH <- v.data
		}
	}
}

func (r *ReliableUDP) ReceiveAll(timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	if r.receiveAllCh == nil {
		return nil, nil, errors.New("please set global receive first")
	}
	if timeout == 0 {
		data := <-r.receiveAllCh
		return data.data, data.addr, nil
	}
	select {
	case data := <-r.receiveAllCh:
		return data.data, data.addr, nil
	case <-time.After(timeout):
		return nil, nil, errors.New("receive all timeout")
	}
}

// 设置全局接收，如果设置了全局接收，那么Receive函数将不再接收数据包，而是将数据包发送到全局接收通道
func (r *ReliableUDP) SetGlobalReceive() {
	if r.receiveAllCh != nil {
		return
	}
	ch := make(chan udpMsg, 100)
	r.receiveAllCh = ch
	//清空dataMap，将数据包发送到全局接收通道ch，可能会导致乱序
	r.mapLock.RLock()
	for k, v := range r.dataMap {
		addr, err := net.ResolveUDPAddr("udp", k)
		if err != nil {
			continue
		}
		tempCh := v
		go func() {
			for data := range tempCh {
				ch <- udpMsg{addr: addr, data: data}
			}
		}()
	}
	r.mapLock.RUnlock()
}

// 关闭连接，关闭前请确保没有调用中的Receive函数和Send函数
func (r *ReliableUDP) Close() {
	if r.close {
		return
	}
	r.close = true
	r.conn.Close()
	r.sendCloseMsg()
	r.mapLock.Lock()
	r.addrMap = nil
	r.dataMap = nil
	r.mapLock.Unlock()
}

func (r *ReliableUDP) sendCloseMsg() {
	for k := range r.addrMap {
		raddr, err := net.ResolveUDPAddr("udp", k)
		if err != nil {
			continue
		}
		go r.sendAck(0, raddr)
	}
}
