package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/netscrt/smart-router/parse"
)

// use socket directly https://gist.github.com/jbenet/5c191d698fe9ec58c49d
// get original destination https://github.com/ryanchapman/go-any-proxy

const SO_ORIGINAL_DST = 80

func checkError(err error) bool {
	if err != nil {
		log.Println(err.Error())
		return true
	}
	return false
}

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:"+parse.Config.Listen)
	if err != nil {
		panic(err)
	}
	for {
		leftConn, err := listener.Accept()
		if checkError(err) {
			continue
		}
		go Route(leftConn)
	}

	fmt.Println("Stop ...")
	time.Sleep(1e9 * 5)
}

func forward(leftConn, rightConn net.Conn) {
	var a struct{}
	closeChan := make(chan struct{})
	go func() {
		io.Copy(leftConn, rightConn)
		closeChan <- a
	}()
	go func() {
		io.Copy(rightConn, leftConn)
		closeChan <- a
	}()
	defer func() {
		leftConnFile, _ := leftConn.(*net.TCPConn).File()
		rightConnFile, _ := rightConn.(*net.TCPConn).File()
		syscall.Close(int(leftConnFile.Fd()))
		syscall.Close(int(rightConnFile.Fd()))
	}()
	<-closeChan
	return
}

func Route(leftConn net.Conn) {
	leftConn, dst, dport := getOriginalDestination(leftConn)
	buf := make([]byte, 10240)
	n, err := leftConn.Read(buf)
	leftConnFile, _ := leftConn.(*net.TCPConn).File()
	leftConnFd := int(leftConnFile.Fd())
	if checkError(err) {
		syscall.Close(leftConnFd)
		return
	}
	fristPack := buf[:n]
	buf = nil
	prot, laddress := parse.GetAddrByRegExp(fristPack)
	lAddr, err := net.ResolveTCPAddr("tcp", laddress+":0")
	if checkError(err) {
		syscall.Close(leftConnFd)
		return
	}

	lsa := NetAddrToSockaddr(lAddr)

	remoteAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%v", dst, dport))
	if checkError(err) {
		syscall.Close(leftConnFd)
		return
	}
	rsa := NetAddrToSockaddr(remoteAddr)

	fd, err := newSocket()
	if checkError(err) {
		syscall.Close(leftConnFd)
		return
	}

	timeoute, _ := time.ParseDuration("5s")
	if err = connect(fd, lsa, rsa, time.Now().Add(timeoute)); err != nil {
		log.Printf("connect failed: %s local addr %s remote addr %s prot %s\n", err, laddress, dst, prot)
		syscall.Close(leftConnFd)
		syscall.Close(fd)
		return
	}

	f := os.NewFile(uintptr(fd), "right connection")
	rightConn, err := net.FileConn(f)
	if checkError(err) {
		syscall.Close(leftConnFd)
		return
	}

	rightConn.Write(fristPack)
	go forward(leftConn, rightConn)
}

func getOriginalDestination(leftConn net.Conn) (net.Conn, string, uint16) {
	tcpConn := leftConn.(*net.TCPConn)
	// connection => file, will make a copy
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		panic(err)
	} else {
		tcpConn.Close()
	}
	addr, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		panic(err)
	}
	// file => connection
	leftConn, err = net.FileConn(tcpConnFile)
	if err != nil {
		panic(err)
	}
	dst := itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	dport := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
	return leftConn, dst, dport
}

// from pkg/net/parse.go
// Convert i to decimal string.
func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}

func newSocket() (fd int, err error) {
	syscall.ForkLock.RLock()
	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		return -1, err
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 2515); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, err
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

var errTimeout = &timeoutError{}

func FD_SET(fd uintptr, p *syscall.FdSet) {
	/*
		n, k := fd/32, fd%32
		p.Bits[n] |= (1 << uint32(k))
	*/
	n := fd >> 6
	if n > 15 {
		log.Printf("Error FdSet index %d out of range", int(n))
	}
	p.Bits[n] |= 1 << (fd & (64 - 1))
}

// this is close to the connect() function inside stdlib/net
func connect(fd int, la, ra syscall.Sockaddr, deadline time.Time) error {
	var err error
	var n int
	//retry:
	if la == nil {
		err = syscall.Connect(fd, ra)
	} else {
		if n == 0 && syscall.Bind(fd, la) != nil {
			panic(err)
		}
		err = syscall.Connect(fd, ra)
	}
	switch err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		/*n += 1
		if n > 10 {
			log.Printf("remote sokete %v retry %d\n", ra, n)
			return err
		}
		goto retry
		*/
	case nil, syscall.EISCONN:
		if !deadline.IsZero() && deadline.Before(time.Now()) {
			return errTimeout
		}
		return nil
	default:
		return err
	}
retry:
	var nerr int
	nerr, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return err
	}
	switch err = syscall.Errno(nerr); err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		goto retry
	case syscall.Errno(0), syscall.EISCONN:
		if !deadline.IsZero() && deadline.Before(time.Now()) {
			return errTimeout
		}
		return nil
	default:
		return err
	}
}

func Select(nfd int, r *syscall.FdSet, w *syscall.FdSet, e *syscall.FdSet, timeout *syscall.Timeval) (n int, err error) {
	return syscall.Select(nfd, r, w, e, timeout)
}

// NetAddrToSockaddr converts a net.Addr to a syscall.Sockaddr.
// Returns nil if the input is invalid or conversion is not possible.
func NetAddrToSockaddr(addr net.Addr) syscall.Sockaddr {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return TCPAddrToSockaddr(addr)
	default:
		return nil
	}
}

// TCPAddrToSockaddr converts a net.TCPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func TCPAddrToSockaddr(addr *net.TCPAddr) syscall.Sockaddr {
	sa := IPAndZoneToSockaddr(addr.IP, addr.Zone)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		sa.Port = addr.Port
		return sa
	case *syscall.SockaddrInet6:
		sa.Port = addr.Port
		return sa
	default:
		return nil
	}
}

// IPAndZoneToSockaddr converts a net.IP (with optional IPv6 Zone) to a syscall.Sockaddr
// Returns nil if conversion fails.
func IPAndZoneToSockaddr(ip net.IP, zone string) syscall.Sockaddr {
	switch {
	case len(ip) < net.IPv4len: // default to IPv4
		buf := [4]byte{0, 0, 0, 0}
		return &syscall.SockaddrInet4{Addr: buf}

	case ip.To4() != nil:
		var buf [4]byte
		copy(buf[:], ip[12:16]) // last 4 bytes
		return &syscall.SockaddrInet4{Addr: buf}

	}
	panic("should be unreachable")
}
