package natTraverse

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/Doraemonkeys/reliableUDP"
)

// func QuicSendMessageQuic(stream quic.Stream, msg Message) error {
// 	data, err := json.Marshal(msg)
// 	if err != nil {
// 		return err
// 	}
// 	var length = int32(len(data))
// 	var buf = new(bytes.Buffer)
// 	err = binary.Write(buf, binary.LittleEndian, length)
// 	if err != nil {
// 		return err
// 	}
// 	err = binary.Write(buf, binary.LittleEndian, data)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = stream.Write(buf.Bytes())
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// func QuicReceiveMessage(stream quic.Stream) (Message, error) {
// 	reader := bufio.NewReader(stream)
// 	var length int32
// 	lengthBuf, _ := reader.Peek(4)
// 	err := binary.Read(bytes.NewReader(lengthBuf), binary.LittleEndian, &length)
// 	if err != nil {
// 		return Message{}, err
// 	}
// 	// Buffered返回缓冲中现有的可读取的字节数。
// 	if int32(reader.Buffered()) < length+4 {
// 		return Message{}, fmt.Errorf("data not enough")
// 	}
// 	// 读取真正的消息数据
// 	data := make([]byte, length+4)
// 	_, err = reader.Read(data)
// 	if err != nil {
// 		return Message{}, err
// 	}
// 	var msg Message
// 	err = msg.unmarshal(data[4:])
// 	if err != nil {
// 		return Message{}, err
// 	}
// 	return msg, nil
// }

func TCPReceiveMessage(conn *net.TCPConn) (Message, error) {
	reader := bufio.NewReader(conn)
	var length int32
	lengthBuf, _ := reader.Peek(4)
	err := binary.Read(bytes.NewReader(lengthBuf), binary.LittleEndian, &length)
	if err != nil {
		return Message{}, err
	}
	// Buffered返回缓冲中现有的可读取的字节数。
	if int32(reader.Buffered()) < length+4 {
		return Message{}, fmt.Errorf("data not enough")
	}
	// 读取真正的消息数据
	data := make([]byte, length+4)
	_, err = reader.Read(data)
	if err != nil {
		return Message{}, err
	}
	var msg Message
	err = msg.unmarshal(data[4:])
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

func TCPSendMessage(conn *net.TCPConn, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var length = int32(len(data))
	var buf = new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, length)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func UDPReceiveMessage(conn *net.UDPConn, timeout time.Duration) (Message, *net.UDPAddr, error) {
	var buf [1024]byte
	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{}) //取消超时
	}
	fmt.Println("UDPReceiveMessage")
	n, addr, err := conn.ReadFromUDP(buf[0:])
	if err != nil {
		return Message{}, nil, err
	}
	var msg Message
	err = msg.unmarshal(buf[0:n])
	if err != nil {
		return Message{}, nil, err
	}
	return msg, addr, nil
}

func UDPSendMessage(conn *net.UDPConn, addr string, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(data, raddr)
	if err != nil {
		return err
	}
	return nil
}

// 调用前需要先调用conn.SetGlobalReceive()
// 不用全局接收后别忘了conn.CancelGlobalReceive()
func RUDPReceiveAllMessage(conn *reliableUDP.ReliableUDP, timeout time.Duration) (Message, *net.UDPAddr, error) {
	data, addr, err := conn.ReceiveAll(timeout)
	if err != nil {
		return Message{}, nil, err
	}
	var msg Message
	//fmt.Println("RUDPReceiveAllMessage", string(data))
	err = msg.unmarshal(data)
	if err != nil {
		return Message{}, nil, err
	}
	return msg, addr, nil
}

func RUDPReceiveMessage(conn *reliableUDP.ReliableUDP, addr *net.UDPAddr, timeout time.Duration) (Message, error) {
	data, err := conn.Receive(addr, timeout)
	if err != nil {
		return Message{}, err
	}
	var msg Message
	err = msg.unmarshal(data)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

func RUDPSendMessage(conn *reliableUDP.ReliableUDP, addr string, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	err = conn.Send(raddr, data, 0)
	if err != nil {
		return err
	}
	return nil
}

func RUDPSendUnreliableMessage(conn *reliableUDP.ReliableUDP, addr string, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	err = conn.SendUnreliable(data, raddr)
	if err != nil {
		return err
	}
	return nil
}

func (m *Message) unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

func UDPRandListen() (udpConn *net.UDPConn, err error) {
	randPort := rand.Intn(20000) + 10000
	fmt.Println("rand port:", randPort)
	laddr, err := net.ResolveUDPAddr("udp4", ":"+fmt.Sprint(randPort))
	if err != nil {
		log.Println("resolve udp addr error", err)
		return
	}
	udpConn, err = net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Println("listen udp error", err)
		return
	}
	return
}

func TCPRandListen() (tcpConn *net.TCPListener, err error) {
	randPort := rand.Intn(20000) + 10000
	fmt.Println("rand port:", randPort)
	laddr, err := net.ResolveTCPAddr("tcp4", ":"+fmt.Sprint(randPort))
	if err != nil {
		log.Println("resolve tcp addr error", err)
		return
	}
	tcpConn, err = net.ListenTCP("tcp4", laddr)
	if err != nil {
		log.Println("listen tcp error", err)
		return
	}
	return
}
