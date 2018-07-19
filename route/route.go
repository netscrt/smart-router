package route

import (
	"log"
	"net"
	"study/golang/network/app_route/parse"
)

func IOBridge(A net.Conn, B net.Conn) {
	go io.Copy(A, B)
	go io.Copy(B, A)
}
func NewBridge(client net.Conn, remoteAddr string, connType string, firstPacket []byte) {
	r, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("客户端%v无法中转到[%s]%s，原因：%s\n", client.RemoteAddr(), connType, remoteAddr, err.Error())
		return
	}
	r.Write(firstPacket)
	go IOBridge(client, r)
	go IOBridge(r, client)
	log.Printf("客户端%v被中转到[%s]%s\n", client.RemoteAddr(), connType, remoteAddr)
}

func NewClientComming(client net.Conn) {
	buf := make([]byte, 20480)
	n, err := client.Read(buf)
	if err != nil {
		log.Printf("客户端%v处理错误，原因:%s\n", client.RemoteAddr(), err)
		client.Close()
		return
	}
	testbuf := buf[:n]
	connType, addr := core.GetAddrByRegExp(testbuf, &testbuf)
	if addr == "" {
		log.Printf("客户端%v处理错误，原因:配置文件中无此协议[%s]的目标中转地址\n", client.RemoteAddr(), connType)
		client.Close()
		return
	}
	NewBridge(client, addr, connType, testbuf)
}

func Route()
