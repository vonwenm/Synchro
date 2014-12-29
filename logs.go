package synchro

import (
		"fmt"
		"code.google.com/p/go.net/websocket"
		"net/http"
		"time"
		)

type MultiLogger struct {
	DevMode bool
	SSL bool
	Host string
	Port string
	AppID string
	Origin string
	WebSocket *websocket.Conn
	DebugChannels map[string]chan string
	DefaultChannel chan string
}

var dummy_channel chan string

func (logger *MultiLogger) NewLog(func_name string) chan string {
	if !logger.DevMode { return logger.DefaultChannel }
	if logger.DebugChannels[func_name] == nil {
		logger.DebugChannels[func_name] = make(chan string, 250)
		go func (logger *MultiLogger, error_channel chan string) {
				s := "#"+<-error_channel+"# "; e := s
				for { if logger.WebSocket != nil { if _, err := logger.WebSocket.Write([]byte(e)); err != nil { break } }; e = s+<- error_channel }
				fmt.Println("ERROR LOGGING TO ERROR CHANNEL", func_name); return
		}(logger, logger.DebugChannels[func_name])
		logger.DebugChannels[func_name] <- func_name
	}
	return(logger.DebugChannels[func_name])
}

func LogConnect(devmode, ssl bool, host string, port, route, appid, origin string) (bool, *MultiLogger) {
	time.Sleep(1 * time.Second)
	port = ":"+port
	logger := &MultiLogger{}
	logger.SSL = ssl
	logger.Host = host
	logger.Port = port
	logger.AppID = appid
	logger.Origin = origin
	protocol := "ws://"
	if logger.SSL { protocol = "wss://" }
	dial_path := protocol+logger.Host+logger.Port+"/"+route+"?app="+appid
	fmt.Println("MULTILOGGER: NEW CONNECTION "+dial_path)
	ws, err := websocket.Dial(dial_path, "", logger.Origin)
	if err != nil { fmt.Println("MULTILOGGER: CONNECT FAILED "+err.Error()); return false, nil }
	logger.WebSocket = ws
	logger.DevMode = devmode
	logger.DebugChannels = make(map[string]chan string)
	logger.DefaultChannel = make(chan string, 999)
	if !devmode { go func () { for { <- logger.DefaultChannel } }() }
	return true, logger
}

func (i *Infrastructure) LogServer(ssl bool, port, route string, handler func(*websocket.Conn)) {
	go func() {
		for {
			http.Handle("/"+route, websocket.Handler(handler))
			fmt.Println("MLOG server listening on "+port+" /"+route)
			port = ":"+port
			e := ""
			if ssl {
				e = http.ListenAndServeTLS(port, i.SSLCertPath, i.SSLKeyPath, nil).Error()
			} else {
				e = http.ListenAndServe(port, nil).Error()
			}
			fmt.Println("MULTILOGGER: !!!! SERVER FAILED "+e)
		}
	}()
}

func LogHandler(ws *websocket.Conn) {
	t := time.Now()
	appid := ws.Request().FormValue("app")
	fmt.Println("RECEIVED CONNECTION FROM", appid, "@", ws.Request().RemoteAddr)
	for {	
		newmessage := ""
		if err := websocket.Message.Receive(ws, &newmessage); err == nil { fmt.Println(appid, t.Format("20060102150405")[8:], newmessage) }
	}
}

func DummyLogChannel() chan string {
	if dummy_channel == nil {
		dummy_channel = make(chan string, 99)
		go func() { for { <-dummy_channel } }()
	}
	return dummy_channel
}