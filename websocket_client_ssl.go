package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const (
	RULE_MAX      = 500000
	TCP_QUICK_ACK = 1
	TCP_NO_DELAY  = 2
)

var outTimeLess1Cnt uint32 = 0
var outTime1to2Cnt uint32 = 0
var outTime2to3Cnt uint32 = 0
var outTime3to4Cnt uint32 = 0
var outTime4to5Cnt uint32 = 0
var outTime5to10Cnt uint32 = 0
var outTime10to15Cnt uint32 = 0
var outTime15to20Cnt uint32 = 0
var outTimeOver20Cnt uint32 = 0
var mineDomain [RULE_MAX]string
var msgHead string = "1111111122222222333333334444444455555555666666667777777788888888"

var addr = flag.String("addr", "nil", "please input addr: Use  -addr . Like -addr 10.91.117.179:8443")
var thread = flag.Int("thread", 0, "please input thread count(Better less 100): Use  -thread ")
var getnum = flag.Int("getnum", 0, "please input get num in each goroutine: Use  -getnum")
var logLevel = flag.Int("logLevel", 5, "Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6. ex: -logLevel 5")
var log *logrus.Logger

func tlsConn() (conn *websocket.Conn, tconn *net.TCPConn, e error) {
	u := url.URL{Scheme: "ws", Host: *addr, Path: "/websocket"}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp4", u.Host)
	if err != nil {
		log.Printf("Resolve Tcp Addr %s failed\n", u.Host)
		return nil, nil, err
	}

	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Printf("Dial %s  failed\n", u.Host)
		return nil, nil, err
	}

	c := tls.Client(tcpConn, conf)
	err = c.Handshake()
	if err != nil {
		log.Printf("Tls hadnshake to %s failed\n", u.Host)
		return nil, nil, err
	}

	wsHeaders := http.Header{
		"Origin":                   {u.Host},
		"Sec-WebSocket-Extensions": {"permessage-deflate; client_max_window_bits, x-webkit-deflate-frame"},
	}

	ws, _, err := websocket.NewClient(c, &u, wsHeaders, 1024, 1024)
	if err != nil {
		log.Fatal("NewClient dial failed:", err)
		return nil, nil, err
	}
	log.Debugf("connecting to %s", u.String())
	return ws, tcpConn, nil
}

func main() {
	flag.Parse()
	if *addr == "nil" {
		log.Errorf("please input addr: Use  -addr . Like -addr 10.91.117.179:8443")
		return
	}
	if *thread == 0 {
		log.Errorf("please input thread count(Better less 100): Use  -thread")
		return
	}
	if *getnum == 0 {
		log.Errorf("please input get num in each goroutine: Use  -getnum")
		return
	}

	LogInit()
	ruleCnt := loadMineFile()
	rand.Seed(time.Now().UnixNano())
	log.Infof("------------------Start a New Test----------------------------")
	log.Infof("    Connecting to       %s    ", *addr)
	log.Infof("    Concurrency cnt:    %d    ", *thread)
	log.Infof("    Each conn test num: %d    ", *getnum)
	log.Infof("    Test seed:          %d    ", ruleCnt)

	var wg sync.WaitGroup
	wg.Add(*thread)
	for i := 1; i <= int(*thread); i++ {
		log.Debugf("-------THREAD(%d) start", i)
		go func(id int) {
			wc, tc, err := tlsConn()
			if err != nil {
				log.Fatalf("dial:", err)
			}
			defer wg.Done()
			defer wc.Close()

			setTcpOption(tc, TCP_NO_DELAY)
			setTcpOption(tc, TCP_QUICK_ACK)

			/*并发，等待其他连接就绪*/
			time.Sleep(3 * time.Second)

			for j := 0; j < int(*getnum); j++ {
				if *thread > 50 {
					time.Sleep(time.Second)
				}

				t := time.Now()
				index := rand.Intn(ruleCnt)
				if len(mineDomain[index]) == 0 {
					log.Debugf("mineDomain[%d] = :%s", index, mineDomain[index])
				}
				key := []byte(msgHead + mineDomain[index])
				log.Debugf("key    :%s", key)
				//key := []byte(msgHead + "guold.net")
				err := wc.WriteMessage(websocket.TextMessage, key)
				if err != nil {
					log.Errorf("write:", err)
					return
				}
				_, message, err := wc.ReadMessage()
				if err != nil {
					log.Errorf("read:", err)
					return
				}
				setTcpOption(tc, TCP_QUICK_ACK)
				log.Debugf("message:%s", message)
				if len(message) <= 32 {
					log.Warnf("can not find key: %s", key)
				}

				/*统计查询延时*/
				tDur := time.Since(t)

				if tDur < 1000000 {
					atomic.AddUint32(&outTimeLess1Cnt, 1)
				} else if (tDur > 1000000) && (tDur < 20000000) {
					atomic.AddUint32(&outTime1to2Cnt, 1)
				} else if (tDur > 2000000) && (tDur < 3000000) {
					atomic.AddUint32(&outTime2to3Cnt, 1)
				} else if (tDur > 3000000) && (tDur < 4000000) {
					atomic.AddUint32(&outTime3to4Cnt, 1)
				} else if (tDur > 4000000) && (tDur < 5000000) {
					atomic.AddUint32(&outTime4to5Cnt, 1)
				} else if (tDur > 5000000) && (tDur < 10000000) {
					atomic.AddUint32(&outTime5to10Cnt, 1)
				} else if (tDur > 10000000) && (tDur < 15000000) {
					atomic.AddUint32(&outTime10to15Cnt, 1)
				} else if (tDur > 10000000) && (tDur < 15000000) {
					atomic.AddUint32(&outTime10to15Cnt, 1)
				} else if (tDur > 15000000) && (tDur < 20000000) {
					atomic.AddUint32(&outTime15to20Cnt, 1)
				} else {
					log.Warnf("----toooooooooooo long time :%v  localaddr:%s  key:%s", tDur, wc.LocalAddr(), mineDomain[index])
					atomic.AddUint32(&outTimeOver20Cnt, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(5 * time.Second)
	log.Infof("------------------------------------------------ ")
	log.Infof("----outTimeCnt     <1ms  :%d ", outTimeLess1Cnt)
	log.Infof("----outTimeCnt   1--2ms  :%d ", outTime1to2Cnt)
	log.Infof("----outTimeCnt   2--3ms  :%d ", outTime2to3Cnt)
	log.Infof("----outTimeCnt   3--4ms  :%d ", outTime3to4Cnt)
	log.Infof("----outTimeCnt   4--5ms  :%d ", outTime4to5Cnt)
	log.Infof("----outTimeCnt  5--10ms  :%d ", outTime5to10Cnt)
	log.Infof("----outTimeCnt 10--15ms  :%d ", outTime10to15Cnt)
	log.Infof("----outTimeCnt 15--20ms  :%d ", outTime15to20Cnt)
	log.Infof("----outTimeCnt    >20ms  :%d ", outTimeOver20Cnt)
	log.Infof("------------------------------------------------ ")
}

func loadMineFile() int {
	var i int
	file, err := os.Open("mine.rules")
	if err != nil {
		log.Errorf("Open mine.rules failed err:%s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	//是否有下一行
	for scanner.Scan() {
		if len(scanner.Text()) > 0 {
			key := strings.Split(scanner.Text(), "|")
			mineDomain[i] = key[0]
			i++
		}
	}
	log.Debugf("--mine rules cnt[%d]\n", i)
	return i
}

func setTcpOption(tcpConn *net.TCPConn, t int) {
	f, err := tcpConn.File()
	if err != nil {
		log.Errorf("tcpConn File error: %s\n", err)
		return
	}
	if t == TCP_QUICK_ACK {
		err = syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	} else if t == TCP_NO_DELAY {
		err = syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	}

	if err != nil {
		log.Errorf("setTcpOption ERROR: %s\n", err)
		return
	}
}

func LogInit() {
	log = logrus.New()
	file, err := os.OpenFile("websocket_client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Infof("Failed to log to file")
	}

	log.SetLevel(logrus.Level(*logLevel))
}
