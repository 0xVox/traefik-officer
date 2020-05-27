package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/hpcloud/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	linesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_officer_lines_processed",
		Help: "Number of access log lines processed",
	})

	linesIgnored = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_officer_lines_ignored",
		Help: "Number of access log lines ignored from latency metrics",
	})

	latencyMetrics = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "traefik_officer_latency_metrics",
		Help:       "Latency metrics per service / endpoint",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	},
		[]string{"router", "RequestPath", "RequestMethod"})
)

type traefikLightConfig struct {
	IgnoredNamespaces []string `json:"IgnoredNamespaces"`
	IgnoredRouters    []string `json:"IgnoredRouters"`
	IgnoredPathsRegex []string `json:"IgnoredPathsRegex"`
}

func main() {
	fileNamePtr := flag.String("log-file", "./accessLog.txt", "The traefik access log file. Default: ./accessLog.txt")
	requestArgsPtr := flag.Bool("include-query-args", false,
		"Set this if you wish for the query arguments to be displayed in the 'RequestPath' in latency metrics. Default: false")
	configLocationPtr := flag.String("config-file", "", "Path to the config file.")
	servePortPtr := flag.String("listen-port", "8080", "Which port to expose metrics on")

	flag.Parse()

	fmt.Println("Access Logs At:", *fileNamePtr)
	fmt.Println("Config File At:", *configLocationPtr)
	fmt.Println("Display Query Args In Metrics: ", *requestArgsPtr)

	go serveProm(*servePortPtr)

	config, err := loadConfig(*configLocationPtr)
	fmt.Printf("Ignoring Namespaces: %s \nIgnoring Routers: %s\n", config.IgnoredNamespaces, config.IgnoredRouters)

	tCfg := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
	}

	fmt.Printf("Opening file\n")
	t, err := tail.TailFile(*fileNamePtr, tCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Starting read\n")

	for line := range t.Lines {
		d, err := parseLine(line.Text)
		if err != nil && err.Error() == "ParseError" {
			continue
		}

		// Push metrics to prometheus exporter
		linesProcessed.Inc()
		latencyStr := strings.Trim(d["Duration"], "ms")
		latency, err := strconv.ParseFloat(latencyStr, 64)
		if err != nil {
			// HTTP Errors turn up here for now
			//fmt.Printf("Error converting %s to float\n", latencyStr)
			//fmt.Printf("From Line: %s", line)
		}

		requestPath := d["RequestPath"]
		if *requestArgsPtr == false {
			requestPath = strings.Split(d["RequestPath"], "?")[0]
		}
		routerName := strings.Trim(d["RouterName"], "\\\"")

		// Check whether routername matches ignored namespace, router or path regex.
		ignoreMatched := (checkMatches(routerName, config.IgnoredNamespaces) ||
			checkMatches(routerName, config.IgnoredRouters) || checkMatches(requestPath, config.IgnoredPathsRegex))

		if ignoreMatched {
			linesIgnored.Inc()
			continue
		}

		// Not ignored, publish metric
		latencyMetrics.WithLabelValues(routerName, requestPath, d["RequestMethod"]).Observe(latency)
	}

}

func checkMatches(str string, matchExpressions []string) bool {
	for i := 0; i < len(matchExpressions); i++ {
		expr := matchExpressions[i]
		reg, err := regexp.Compile(expr)

		if err != nil {
			fmt.Printf("Error compiling regex: %s \n", expr)
		}

		if reg.MatchString(str) {
			//fmt.Printf("Regex %s matches %s", expr, str)
			return true
		}
	}
	return false
}

func parseLine(line string) (map[string]string, error) {
	var buffer bytes.Buffer                      // Stolen from traefik repo pkg/middlewares/accesslog/parser.go
	buffer.WriteString(`(\S+)`)                  // 1 - ClientHost
	buffer.WriteString(`\s-\s`)                  // - - Spaces
	buffer.WriteString(`(\S+)\s`)                // 2 - ClientUsername
	buffer.WriteString(`\[([^]]+)\]\s`)          // 3 - StartUTC
	buffer.WriteString(`"(\S*)\s?`)              // 4 - RequestMethod
	buffer.WriteString(`((?:[^"]*(?:\\")?)*)\s`) // 5 - RequestPath
	buffer.WriteString(`([^"]*)"\s`)             // 6 - RequestProtocol
	buffer.WriteString(`(\S+)\s`)                // 7 - OriginStatus
	buffer.WriteString(`(\S+)\s`)                // 8 - OriginContentSize
	buffer.WriteString(`("?\S+"?)\s`)            // 9 - Referrer
	buffer.WriteString(`("\S+")\s`)              // 10 - User-Agent
	buffer.WriteString(`(\S+)\s`)                // 11 - RequestCount
	buffer.WriteString(`("[^"]*"|-)\s`)          // 12 - FrontendName
	buffer.WriteString(`("[^"]*"|-)\s`)          // 13 - BackendURL
	buffer.WriteString(`(\S+)`)                  // 14 - Duration

	regex, err := regexp.Compile(buffer.String())
	if err != nil {
		//fmt.Printf("Error parsing access log line: '%s'\n", line)
		err = errors.New("ParseError")
	}

	submatch := regex.FindStringSubmatch(line)
	result := make(map[string]string)

	if len(submatch) > 13 {
		result["ClientHost"] = submatch[1]
		result["ClientUsername"] = submatch[2]
		result["StartUTC"] = submatch[3]
		result["RequestMethod"] = submatch[4]
		result["RequestPath"] = submatch[5]
		result["RequestProtocol"] = submatch[6]
		result["OriginStatus"] = submatch[7]
		result["OriginContentSize"] = submatch[8]
		result["RequestRefererHeader"] = submatch[9]
		result["RequestUserAgentHeader"] = submatch[10]
		result["RequestCount"] = submatch[11]
		result["RouterName"] = submatch[12]
		result["ServiceURL"] = submatch[13]
		result["Duration"] = submatch[14]
		return result, nil
	}

	//fmt.Printf("Line not in access log format: %s", line)
	err = errors.New("Access Log Line Invalid")
	return nil, err
}

func loadConfig(configLocation string) (traefikLightConfig, error) {
	cfgFile, err := os.Open(configLocation)
	if err != nil {
		fmt.Printf("Error opening config file: %s", configLocation)
		var emptyConf traefikLightConfig
		return emptyConf, err
	}
	defer cfgFile.Close()
	var config traefikLightConfig

	byteValue, _ := ioutil.ReadAll(cfgFile)

	json.Unmarshal(byteValue, &config)
	return config, nil
}

func serveProm(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":"+port, nil)
}
