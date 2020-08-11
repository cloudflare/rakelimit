package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cloudflare/rakelimit/targetlimit"
)

var (
	// Source Port Stage
	srcPortLimit = targetlimit.Limit{
		PacketsPerSecond: float64(100),
		BurstSec:         float64(5),
	}

	// Source Net Stage
	srcNetLimit = targetlimit.Limit{
		PacketsPerSecond: float64(100),
		BurstSec:         float64(5),
	}

	// Source IP Stage
	srcIPLimit = targetlimit.Limit{
		PacketsPerSecond: float64(100),
		BurstSec:         float64(5),
	}

	// Destination IP/Port Stage
	dstLimit = targetlimit.Limit{
		PacketsPerSecond: float64(100),
		BurstSec:         float64(5),
	}
)

var conn *net.UDPConn

func reporter(tl *targetlimit.TargetLimit) {
	listener, err := net.Listen("tcp", "127.0.0.1:3131")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Can't accept reporter connetion: %v", err)
			continue
		}
		msg := fmt.Sprintf("%20s: %6d\n", "SrcPortDrop", tl.GetDropSrcPortStat())
		msg += fmt.Sprintf("%20s: %6d\n", "SrcNetDrop", tl.GetDropSrcNetStat())
		msg += fmt.Sprintf("%20s: %6d\n", "SrcIPDrop", tl.GetDropSrcIPStat())
		msg += fmt.Sprintf("%20s: %6d\n", "DestIPPortDrop", tl.GetDropDstIPPortStat())
		msg += fmt.Sprintf("%20s: %6d\n", "Errors", tl.GetErrorStat())
		msg += fmt.Sprintf("%20s: %6d\n\n", "Total", tl.GetTotalStat())
		conn.Write([]byte(msg))
		conn.Close()
	}
}

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2323})
	if err != nil {
		log.Fatalf("[-] Can't listen on UDP: %v", err)
	}
	defer conn.Close()

	// Create Rate limiter
	tl, err := targetlimit.NewTargetLimit(srcPortLimit, srcNetLimit, srcIPLimit, dstLimit)
	if err != nil {
		log.Fatalf("Can't create target limiter: %v", err)
	}
	tl.EbpfLnAttach(conn)
	go reporter(tl)

	msg := make([]byte, 1024)
	for {
		bytesRead, raddr, err := conn.ReadFrom(msg)
		if err != nil {
			log.Printf("[-] Error reading UDP packet: %v", err)
			continue
		}
		log.Printf("[*] Read %d bytes", bytesRead)
		conn.WriteTo([]byte{0x41, 0x41, 0x41, 0x41}, raddr)
	}
}
