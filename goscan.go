package goscan

import (
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
)

// Scanner Address routing properties and handle to for reading and writing on interface
// ref: https://github.com/google/gopacket/blob/master/examples/synscan/main.go#L35
type Scanner struct {
	// Iface is the interface to send packets on.
	Iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	Gw, Src net.IP
	Dst     *net.IPNet
	Ports   []int

	Rps     int
	Timeout int

	// Opts and buf allow us to easily serialize packets in the send()
	// method.
	Opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// NewScanner create scanner object using routing table object
func NewScanner(ip *net.IPNet, pArr []int, router routing.Router, rps int, timeout int) (*Scanner, error) {
	s := &Scanner{
		Dst:   ip,
		Ports: pArr,
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:     gopacket.NewSerializeBuffer(),
		Rps:     rps,
		Timeout: timeout,
	}

	iface, gw, src, err := router.Route(ip.IP)
	if err != nil {
		return nil, err
	}

	// set gateway, src ip, and interface in scanner using routing table
	s.Gw, s.Src, s.Iface = gw, src, iface

	// return scanner object
	return s, nil

}

// GetFreePort hack to get a an available tcp port
// ref: https://github.com/phayes/freeport/blob/master/freeport.go#L7
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// simple contains func
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// PortState [state 0 = open || 1 = closed]
type PortState struct {
	Addr  string
	Port  int
	State int
}

// type queueEntry struct {
// 	Addr net.Addr
// 	Port layers.TCPPort
// }

// func queueContains(s []queueEntry, e queueEntry) bool {
// 	for _, a := range s {
// 		if a == e {
// 			return true
// 		}
// 	}
// 	return false
// }

// removes element and returns true if element is contain within slice
func uint32Contains(s []uint32, e uint32) bool {
	// for i := 0; i< len(s); i++{
	// 	if s[i] == e {
	// 		s = append(s[:i], s[i+1:]...)
	// 		return true
	// 	}
	// }
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Scan run scan on scanner object, use buffered channels
func (s *Scanner) Scan(c chan PortState, e chan error) {
	// var results []PortState
	rand.Seed(time.Now().UnixNano())

	// requests per second
	rps := time.Tick(time.Second / time.Duration(s.Rps))
	// timeout after requests finish
	timeout := s.Timeout

	// setup conn handle
	// don't have to worry about ethernet frame vs pcap openlive
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		close(c)

		e <- err
		close(e)
		return
	}
	defer conn.Close()

	// get an available source port
	rawPort, err := GetFreePort()
	if err != nil {
		close(c)

		e <- err
		close(e)
		return
	}

	// Construct all the network layers we need.
	// eth := layers.Ethernet{
	// 	SrcMAC:       s.iface.HardwareAddr,
	// 	DstMAC:       hwaddr,
	// 	EthernetType: layers.EthernetTypeIPv4,
	// }
	ip4 := layers.IPv4{
		SrcIP:    s.Src,
		DstIP:    net.ParseIP("0.0.0.0"), // set value to destination ip when scanning
		Version:  4,
		TTL:      225,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: layers.TCPPort(0), // set value to destination port when scanning
		SYN:     true,
		Seq:     uint32(1000000000), // generate random sequence number
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	var ackNums []uint32

	go func() {
		data := make([]byte, 4096)
		// var queue []queueEntry
		for {
			n, addr, err := conn.ReadFrom(data)

			// conn.Close() closes goroutine and ends listener
			if err != nil {
				break
			}

			// ip in cidr
			if !s.Dst.Contains(net.ParseIP(addr.String()).To4()) {
				continue
			}

			packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}
				// We consider only incoming packets
				if tcp.DstPort != layers.TCPPort(rawPort) {
					continue
				}

				// TODO: remove matching acknowledgment numbers
				// should I mutex lock?
				if !uint32Contains(ackNums, tcp.Ack) {
					continue
				}

				// open ports
				if tcp.SYN && tcp.ACK {
					// log.Printf("%v port %v open", addr.String(), tcp.SrcPort)

					// go routine shouldn't manage go channel buffers
					// for {
					// 	if len(c) == cap(c) {
					// 		continue
					// 	} else {
					c <- PortState{addr.String(), int(tcp.SrcPort), 0}
					// 		break
					// 	}
					// }
					// results = append(results, PortState{addr.String(), int(tcp.SrcPort), 0})
				}
				// closed ports
				if tcp.RST {
					// log.Printf("%v port %v closed", addr.String(), tcp.SrcPort)

					// for {
					// 	if len(c) == cap(c) {
					// 		continue
					// 	} else {
					c <- PortState{addr.String(), int(tcp.SrcPort), 1}
					// 		break
					// 	}
					// }
					// results = append(results, PortState{addr.String(), int(tcp.SrcPort), 1})
				}
			}
		}
	}()

	// wg := &sync.WaitGroup{}
	// wg.Add(1)

	// go func() {
	// defer wg.Done()
	ip := s.Dst.IP
	for ip := ip.Mask(s.Dst.Mask); s.Dst.Contains(ip); inc(ip) {
		// set ip address of packet
		ip4.DstIP = ip.To4()
		for _, port := range s.Ports {
			<-rps

			// fmt.Printf("%v %v\n", ip, port)
			// set port to send SYN packet
			tcp.DstPort = layers.TCPPort(port)

			randSeq := 1000000000 + rand.Intn(math.MaxInt32)
			tcp.Seq = uint32(randSeq)

			ackNums = append(ackNums, tcp.Seq+1)

			// send packed
			// err = s.send(&eth, &ip4, &tcp)
			_, err := s.send(conn, ip, &tcp)
			if err != nil {
				// host down/doesn't exist
				// log.Printf("error sending packet to port %v: %v", tcp.DstPort, err)
			}
		}
	}
	// }()
	// wg.Wait()

	if timeout > 0 {
		// async timer
		// timer := time.AfterFunc(time.Duration(timeout)*time.Second, func() {
		// 	conn.Close()
		// })
		// defer timer.Stop()

		time.Sleep(time.Duration(timeout) * time.Millisecond)
	} else {
		conn.Close()
	}

	close(c)

	e <- nil
	close(e)
	return
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(conn net.PacketConn, dst net.IP, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.Opts, l...); err != nil {
		return 0, err
	}
	return conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dst})
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// SetupScanner setup a scanner
func SetupScanner(ipRange string, ports []int, rps int, timeout int) *Scanner {
	// ip is stored as 16 by default, comparisons will fail if byte size are missmatched
	// ip := net.ParseIP("172.217.13.100").To4()
	_, ipnet, err := net.ParseCIDR(ipRange)

	// create routing table from system routes
	router, err := routing.New()
	if err != nil {
		log.Printf("routing error: %v", err)
		return nil
	}

	// scanner init
	s, err := NewScanner(ipnet, ports, router, rps, timeout)
	if err != nil {
		log.Printf("unable to create scanner: %v", err)
		return nil
	}

	return s
}

//Options struct to hold flags
type Options struct {
	Range    string
	Ports    string
	Requests int
	Timeout  int
}

//Run function parses options and runs scanner to print output, nothin returned
func Run(options *Options) {
	// remove timestamp from logs
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	var ports []int
	sPorts := strings.Split(options.Ports, ",")
	ports = make([]int, len(sPorts))
	for i, s := range sPorts {
		ports[i], _ = strconv.Atoi(s)
	}

	// requests per second
	rps := options.Requests
	// timeout in milliseconds after packet is sent
	timeout := options.Timeout

	s := SetupScanner(options.Range, ports, rps, timeout)

	log.Printf("scanning ip %s with interface %v, gateway %v, src %v", s.Dst.String(), s.Iface.Name, s.Gw, s.Src)

	// setup channels and scan
	c := make(chan PortState, 1)
	e := make(chan error, 1)
	go s.Scan(c, e)

	// parse results while scanning
	for i := range c {
		if i.State == 0 {
			log.Printf("%s port %v open", i.Addr, i.Port)
		}
		if i.State == 1 {
			log.Printf("%s port %v closed", i.Addr, i.Port)
		}
	}
	err := <-e
	if err != nil {
		log.Printf("unable to scan %s: %v", options.Range, err)
	}
}
