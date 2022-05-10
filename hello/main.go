package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

func main() {
	port := flag.String("port", "8080", "Listen Port")
	host := flag.String("host", "192.168.132.121", "Listen Host")
	flag.Parse()

	srv, err := net.Listen("tcp", fmt.Sprint(*host, ":", *port))
	if err != nil {
		log.Panicln(err)
	}
	defer func(srv net.Listener) {
		err = srv.Close()
		if err != nil {
			log.Panicln(err)
		}
	}(srv)
	log.Println("Listening to connections at '"+*host+"' on port", *port)

	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Panicln(err)
		}

		go sayHello(conn)
	}
}

func sayHello(conn net.Conn) {
	log.Println("【 New connection 】", conn.RemoteAddr().String(), "-->", conn.LocalAddr().String())
	conn.Write([]byte("Hello it's me! You say what, I say what! Let's start:\n"))
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println(err)
		}
	}(conn)
	defer log.Println("【Close connection】", conn.RemoteAddr().String(), "-->", conn.LocalAddr().String())

	for {
		buf := make([]byte, 1024)
		size, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:size]
		t, _ := GbkToUtf8(data)
		log.Println("【   Received     】", conn.RemoteAddr().String(), "-->", conn.LocalAddr().String(), "【", strings.ReplaceAll(string(t), "\n", ""), "】")
		conn.Write(data)
	}
}

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}
