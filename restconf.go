package controllers

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

const (
	TLSHBON = iota
	TLSHBOFF
)

type TLSHBConfig struct {
	HbInterval int
	HbMaxLost  int
	HbEnable   bool
}

type TLSHBStatus struct {
	HbLost     int
	HbStatus   int
	HbLastTime time.Time
}

type RestconfReq struct {
	Method  string
	URI     string
	Query   url.Values
	Version string
	Header  map[string]string
	Body    string
}

type RestconfClient struct {
	Host         string
	Port         int
	TLSConfig    *tls.Config
	TLSKeepAlive bool
	TLSConn      *tls.Conn
	TLSHbConfig  *TLSHBConfig
	TLSHbStatus  *TLSHBStatus
}

func (cli *RestconfClient) Dial() (conn *tls.Conn, err error) {
	if cli.TLSConn != nil {
		cli.TLSConn.Close()
		cli.TLSConn = nil
	}

	if cli.Host == "" || cli.Port <= 0 {
		return nil, fmt.Errorf("invalid host[%s] or port[%d]", cli.Host, cli.Port)
	}

	if cli.TLSConfig == nil {
		cli.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	addr := cli.Host + ":" + strconv.Itoa(cli.Port)
	cli.TLSConn, err = tls.Dial("tcp", addr, cli.TLSConfig)
	return cli.TLSConn, err
}

func (req RestconfReq) Construct() string {
	ret := req.Method + " " + req.URI + " "
	if req.Query != nil {
		ret += "?" + url.Values.Encode(req.Query)
	}

	ret += "\r\n"
	if _, ok := req.Header["Content-Length"]; !ok && req.Body != "" {
		req.Header["Content-Length"] = strconv.Itoa(len(req.Body))
	}
	for k, v := range req.Header {
		ret += k + ":" + v + "\r\n"
	}

	ret += "\r\n"
	ret += req.Body
	return ret
}

func (cli *RestconfClient) Close() {
	if cli.TLSConn != nil {
		cli.TLSConn.Close()
	}
}

func (cli *RestconfClient) DoRestconf(req *RestconfReq) ([]byte, error) {
	if cli.TLSConn == nil {
		_, err := cli.Dial()
		if err != nil {
			return nil, err
		}
	}

	reqStr := req.Construct()
	reqStrlen := len(reqStr)
	for reqStrlen > 0 {
		n, err := cli.TLSConn.Write([]byte(reqStr))
		if err != nil {
			return nil, err
		}

		reqStrlen -= n
	}

	buf := make([]byte, 1024)
	_, err := cli.TLSConn.Read(buf)
	if err != nil {
		return nil, err
	}

	if !cli.TLSKeepAlive {
		cli.Close()
	}

	return buf, nil
}

func (cli *RestconfClient) GetHbStatus() *TLSHBStatus {
	if cli.TLSHbStatus != nil {
		var hbStatus TLSHBStatus
		hbStatus = *(cli.TLSHbStatus)
		return &hbStatus
	}

	return nil
}
