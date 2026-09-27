//go:build ignore

// Command livecheck is a runtime probe harness for the audit smoke test. It talks
// to an already-running re0auth over HTTP and reports what actually came back, so
// the audit's claims about the live surface are measurements rather than readings.
//
// Usage: go run ./internal/zzprobe/livecheck <case>
//
//	ratelimit  - is the limiter bucket keyed by the peer address, or can a forged
//	             X-Forwarded-For choose its own bucket?
//	burst      - raw arrival rate the limiter actually sheds at
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var base = flag.String("base", "http://127.0.0.1:8080", "base URL of the running server")

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "need a case: ratelimit | burst")
		os.Exit(2)
	}
	switch args[0] {
	case "ratelimit":
		rateLimitCase()
	case "burst":
		burstCase()
	case "reject":
		rejectCase()
	default:
		fmt.Fprintln(os.Stderr, "unknown case", args[0])
		os.Exit(2)
	}
}

// get issues one request, optionally with a forged X-Forwarded-For, and returns
// the status code. The body is drained so the connection can be reused.
func get(client *http.Client, path, xff string) int {
	req, err := http.NewRequest(http.MethodGet, *base+path, nil)
	if err != nil {
		return -1
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// rateLimitCase runs two bursts against the same business-plane path: one where
// every request claims the same forwarded address, and one where each request
// claims a different one. If the limiter keys on the peer address (the documented
// behaviour with an empty trusted_proxies list) both bursts shed load at roughly
// the same point. If a forged header buys a fresh bucket, the second burst never
// sees a 429.
func rateLimitCase() {
	client := &http.Client{Timeout: 10 * time.Second}
	const path = "/v1/audit-probe-nonexistent"

	run := func(label string, xff func(i int) string) {
		counts := map[int]int{}
		first429 := -1
		for i := 0; i < 400; i++ {
			code := get(client, path, xff(i))
			counts[code]++
			if code == http.StatusTooManyRequests && first429 < 0 {
				first429 = i + 1
			}
		}
		fmt.Printf("%-34s first429=%d  ", label, first429)
		for _, c := range []int{200, 404, 429, 503, -1} {
			if counts[c] > 0 {
				fmt.Printf("%d=%d ", c, counts[c])
			}
		}
		fmt.Println()
	}

	// Let the bucket refill between the two bursts.
	run("fixed XFF (10.0.0.1)", func(int) string { return "10.0.0.1" })
	time.Sleep(4 * time.Second)
	run("rotating XFF (10.0.1.i)", func(i int) string { return fmt.Sprintf("10.0.1.%d", i%250+1) })
}

// rejectCase drives one plane past its budget and reports what the rejection
// actually looks like: the status, the plane's error shape, and whether the
// client is told when to come back.
func rejectCase() {
	client := &http.Client{Timeout: 10 * time.Second}
	for _, path := range []string{"/v1/audit-probe-nonexistent", "/oauth/token"} {
		var rejected *http.Response
		var body []byte
		for i := 0; i < 400; i++ {
			method := http.MethodGet
			if path == "/oauth/token" {
				method = http.MethodPost
			}
			req, _ := http.NewRequest(method, *base+path, nil)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println(path, "transport error:", err)
				break
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				rejected, body = resp, b
				break
			}
		}
		fmt.Printf("--- %s\n", path)
		if rejected == nil {
			fmt.Println("    no 429 produced in 400 requests")
			continue
		}
		fmt.Printf("    status=%d content-type=%q\n", rejected.StatusCode, rejected.Header.Get("Content-Type"))
		fmt.Printf("    Retry-After=%q RateLimit-Limit=%q RateLimit-Remaining=%q RateLimit-Reset=%q\n",
			rejected.Header.Get("Retry-After"),
			rejected.Header.Get("RateLimit-Limit"),
			rejected.Header.Get("RateLimit-Remaining"),
			rejected.Header.Get("RateLimit-Reset"))
		if len(body) > 200 {
			body = body[:200]
		}
		fmt.Printf("    body=%s\n", body)
	}
}

// burstCase measures how many requests actually get shed under concurrency, which
// is the number that matters for a brute-force budget.
func burstCase() {
	const workers = 32
	const each = 60
	var ok, limited, other, failed int64
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: workers}}
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				switch get(client, "/v1/audit-probe-nonexistent", "") {
				case http.StatusTooManyRequests:
					atomic.AddInt64(&limited, 1)
				case 404, 401, 403:
					atomic.AddInt64(&ok, 1)
				case -1:
					atomic.AddInt64(&failed, 1)
				default:
					atomic.AddInt64(&other, 1)
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	total := workers * each
	fmt.Printf("burst: %d requests in %s (%.0f req/s)\n", total, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())
	fmt.Printf("  shed (429): %d   served (4xx): %d   other: %d   transport errors: %d\n", limited, ok, other, failed)
	if limited == 0 {
		fmt.Println("  NOTE: nothing was shed -- either the limiter is off for this path or the arrival rate is under the limit")
	}
}
