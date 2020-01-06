package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/exec"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const (
	HEAD_LEN      = 64
	TCP_QUICK_ACK = 1
	TCP_NO_DELAY  = 2
)

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>  
window.addEventListener("load", function(evt) {

    var output = document.getElementById("output");
    var input = document.getElementById("input");
    var ws;

    var print = function(message) {
        var d = document.createElement("div");
        d.innerHTML = message;
        output.appendChild(d);
    };

    document.getElementById("open").onclick = function(evt) {
        if (ws) {
            return false;
        }
        ws = new WebSocket("{{.}}");
        ws.onopen = function(evt) {
            print("OPEN");
        }
        ws.onclose = function(evt) {
            print("CLOSE");
            ws = null;
        }
        ws.onmessage = function(evt) {
            print("RESPONSE: " + evt.data);
        }
        ws.onerror = function(evt) {
            print("ERROR: " + evt.data);
        }
        return false;
    };

    document.getElementById("send").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        print("SEND: " + input.value);
        ws.send(input.value);
        return false;
    };

    document.getElementById("close").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        ws.close();
        return false;
    };

});
</script>
</head>
<body>
<table>
<tr><td valign="top" width="50%">
<p>Click "Open" to create a connection to the server, 
"Send" to send a message to the server and "Close" to close the connection. 
You can change the message and send multiple times.
<p>
<form>
<button id="open">Open</button>
<button id="close">Close</button>
<p><input id="input" type="text" value="Hello world!">
<button id="send">Send</button>
</form>
</td><td valign="top" width="50%">
<div id="output"></div>
</td></tr></table>
</body>
</html>
`))

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var FAILED = errors.New("FAILED")
var RedisPasswordPath string = "/opt/nubosh/vmsec-ctrl/redis/conf/redis_threatInfo.conf"
var Cmd string = "/opt/nubosh/vmsec-ctrl/bin/aescrypt"
var MineRulesEnc string = "/opt/nubosh/vmsec-ctrl/data/ioc/mine.rules"
var MineRulesDec string = "/opt/nubosh/vmsec-ctrl/data/ioc/mine_dec.rules"
var LogFile string = "/opt/nubosh/commonlog/bin/log/websocket_server.log"
var CpuProfLogFile string = "/opt/nubosh/commonlog/bin/log/websocket_server_CPU_prof"
var MemProfLogFile string = "/opt/nubosh/commonlog/bin/log/websocket_server_Mem_prof"

var RedisPasswd string   //保存从redis.conf文件中提取出来的redis密码
var gMineRules sync.Map  //本地缓存数据，用于快速查询
var gRedisConn sync.Map  //保存client和链接redis的对应关系
var gOutTimeCnt uint32   //超时数据统计
var log *logrus.Logger   //记录日志的句柄
var cpuProfFile *os.File //性能统计的文件句柄
var memProfFile *os.File //内存统计的文件句柄

var logLevel = flag.Int("logLevel", 4, "Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6. ex: -logLevel 5")
var addr = flag.String("addr", "localhost:33873", "http service address")

type RpcCmd int //RPC的对象

type RedisConn struct {
	conn        redis.Conn
	statTimeout uint32
}

/* client连接，传输数据处理函数 */
func echo(w http.ResponseWriter, r *http.Request) {
	log.Debugf("recv:echo")
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("Upgrade error: %s", err)
		return
	}
	connnectRedis(c)
	setTcpOption(c.GetNetConn(), TCP_NO_DELAY)
	defer connClose(c)

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Errorf("IsUnexpectedCloseError : %s", err)
			}
			break
		}
		log.Debugf("recv: %+v,  len:%d", message, len(message))
		if len(message) < HEAD_LEN {
			log.Debugf("message len should be > %d", HEAD_LEN)
			return
		}
		head := message[:HEAD_LEN]
		key := message[HEAD_LEN:]
		log.Debugf("key: %s", key)
		t := time.Now()
		val, _ := searchMineRules(string(key), c)
		tDur := time.Since(t)
		if tDur > 2000000 {
			atomic.AddUint32(&gOutTimeCnt, 1)
			log.Warnf("get %s  time out :  %v  cnt(%v)", key, tDur, gOutTimeCnt)
		}
		log.Debugf("data: %s", val)
		data := append(head[:], []byte(val)...)
		err = c.WriteMessage(mt, data)
		if err != nil {
			log.Errorf("write error: %s", err)
			break
		}
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Recv home: %s", r.Host)
	homeTemplate.Execute(w, "ws://"+r.Host+"/websocket")
}

func connnectRedis(c *websocket.Conn) {
	log.Debugf("conn %s connnect Redis", c.LocalAddr())
	var err error
	if val, ok := gRedisConn.Load(c); ok {
		log.Warnf("%s redis already connected,  %v", c.LocalAddr(), val)
		return
	}

	conn, err := redis.Dial("tcp", "127.0.0.1:9736", redis.DialPassword(RedisPasswd))
	if err != nil {
		log.Errorf("Connect to redis error: %s", err)
		return
	}
	redisConn := RedisConn{conn, 0}
	gRedisConn.Store(c, redisConn)
}

/*启动定时器，每12小时把mine.rules刷入本地数据区，更新数据*/
func updateMineRuleLocal() {
	loadMineRule()

	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			loadMineRule()
		}
	}
}

/*把mine.rules刷入本地数据区*/
func loadMineRule() {
	var err error
	var wg sync.WaitGroup

	log.Debugf("Update mine.rules to local")
	/*要把mine.rules文件先解密，调用脚本解密*/
	cmd := exec.Command(Cmd, "-dec", MineRulesEnc, MineRulesDec)
	if err := cmd.Run(); err != nil {
		log.Errorf("aescrypt dec failed", err)
		return
	}

	gMineRules.Range(func(k, v interface{}) bool {
		gMineRules.Delete(k)
		return true
	})

	ch := make(chan string, 10000)
	rdDonech := make(chan bool)

	wg.Add(1)
	go func() {
		var cnt uint32
		defer wg.Done()
		for {
			select {
			case val := <-ch:
				key := strings.Split(val, "|")
				gMineRules.Store(key[0], (val + "|1")) //这个是加了黑名单，白名单的标记位，1黑2白
				cnt++
			default:
				select {
				case val := <-ch:
					key := strings.Split(val, "|")
					gMineRules.Store(key[0], (val + "|1"))
					cnt++
				case <-rdDonech:
					log.Debugf("WriteDone-- final write redis cnt:%d", cnt)
					return
				default:
					continue
				}
			}
		}
	}()

	file, err := os.Open(MineRulesDec)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	//是否有下一行
	for scanner.Scan() {
		log.Trace("--scanner.Text()--:%s", scanner.Text())
		if len(scanner.Text()) > 0 {
			ch <- scanner.Text()
		}
	}
	rdDonech <- true

	wg.Wait()
	/*要把mine.rules的解密文件mine_dec.rules删掉*/
	cmd = exec.Command("rm", "-r", "-f", MineRulesDec)
	if err := cmd.Run(); err != nil {
		log.Errorf("delete mine_dec.rules failed, %s", err)
		return
	}
}

/*用于设置TCP的option， TCP_QUICKACK 和 TCP_NODELAY*/
func setTcpOption(conn net.Conn, t int) {
	tcpConn := conn.(*net.TCPConn)

	f, err := tcpConn.File()
	if err != nil {
		log.Errorf("tcpConn File error: %s", err)
		return
	}
	if t == TCP_QUICK_ACK {
		err = syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	} else if t == TCP_NO_DELAY {
		err = syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	}

	if err != nil {
		log.Errorf("setTcpOption ERROR: %s", err)
		return
	}
}

/*获取redis.conf的密码*/
func GetRedisPassword() string {
	file, err := os.Open(RedisPasswordPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		log.Trace("GetRedisPassword --scanner.Text()--:%s\n", scanner.Text())
		if len(scanner.Text()) > 0 {
			if strings.Contains(scanner.Text(), "masterauth") {
				tmpStr := scanner.Text()
				tmpStr = strings.Replace(tmpStr, " ", "", -1)
				pw := strings.Split(tmpStr, "masterauth")
				return pw[1]
			}
		}
	}
	return "ac401b00381832cfe560d811a4e7f665"
}

/*关闭websocket，释放资源*/
func connClose(c *websocket.Conn) {
	gRedisConn.Delete(c)
	c.Close()
}

/*查找rule，先查本地local cache，查不到就去查redis*/
func searchRule(key string, c *websocket.Conn) (val string, err error) {
	if rule, ok := gMineRules.Load(string(key)); ok {
		val = rule.(string)
		return val, nil
	} else {
		value, _ := gRedisConn.Load(c)
		val, err = redis.String(value.(RedisConn).conn.Do("GET", key))
		if err != nil {
			log.Errorf("redis get key(%s) failed:%s", key, err)
			return "", FAILED
		}
		return val, nil
	}
}

/*
查找domain，如果查不到，就查顶级域名
     普通域名                                  顶级域名
  www.tull.coin-miners.info  ------------  *coin-miners.info
  altcoinpool.com            ------------  *altcoinpool.com
*/
func searchMineRules(key string, c *websocket.Conn) (val string, err error) {
	val, err = searchRule(key, c)
	if err == nil {
		return val, nil
	}
	var domain string
	cnt := strings.Count(key, ".")
	if cnt > 1 {
		tmp := strings.Split(key, ".")
		domain = fmt.Sprintf("*%s.%s", tmp[cnt-1], tmp[cnt])
		log.Debugf("Search again --, domin: %s", domain)
	} else if cnt == 1 {
		isDomain := strings.Count(key, "*")
		if isDomain == 0 {
			domain = fmt.Sprintf("*%s", key)
			log.Debugf("search again __, domin: %s", domain)
		}
	} else {
		domain = key
	}

	val, err = searchRule(domain, c)
	if err == nil {
		return val, nil
	}
	return "", FAILED
}

/*初始化日志*/
func LogInit() {
	log = logrus.New()
	file, err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Errorf("Failed to log to file")
	}
	log.SetLevel(logrus.Level(*logLevel))
}

/*RPC框架调试函数，对当前进程开启CPU prof的打点*/
func (t *RpcCmd) GoprofBegin(args *int, reply *int) error {
	cpuProfFile, err := os.OpenFile(CpuProfLogFile, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Errorf("Failed to CPU prof log to file. %s", err)
		return nil
	}

	err = pprof.StartCPUProfile(cpuProfFile)
	if err != nil {
		log.Errorf("Can not start cpu profile: %s", err)
	}
	return nil
}

/*RPC框架调试函数，关闭当前进程CPU prof的打点*/
func (t *RpcCmd) GoprofEnd(args *int, reply *int) error {
	pprof.StopCPUProfile()
	cpuProfFile.Close()
	return nil
}

/*RPC框架，调试函数，获取当前进程的Mem prof*/
func (t *RpcCmd) MemProf(args *int, reply *int) error {
	memProfFile, err := os.OpenFile(MemProfLogFile, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Errorf("Failed to mem prof log to file. %s", err)
		return nil
	}
	defer memProfFile.Close()

	pprof.Lookup("heap").WriteTo(memProfFile, 1)
	return nil
}

/*RPC框架调试函数，设置debug级别*/
func (t *RpcCmd) SetLogLevel(level *int, reply *int) error {
	log.Warnf("Log level will be set :%d", *level)
	log.SetLevel(logrus.Level(*level))
	*reply = 1
	return nil
}

/*rpc的server端，提供端口为1234的服务，供client端远程调用调试函数*/
func rpcServer() {
	cmd := new(RpcCmd)
	rpc.Register(cmd)
	rpc.HandleHTTP()
	l, e := net.Listen("tcp", ":1234")
	if e != nil {
		log.Errorf("listen error:", e)
	}
	go http.Serve(l, nil)
}

func main() {
	flag.Parse()
	LogInit()
	log.Infof("--------------Websocket Server Begin----------------")
	go rpcServer()
	go updateMineRuleLocal()
	RedisPasswd = GetRedisPassword()
	http.HandleFunc("/websocket", echo)
	http.HandleFunc("/", home)
	http.ListenAndServe(*addr, nil)
}
