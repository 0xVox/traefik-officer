package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/hpcloud/tail"
	ps "github.com/mitchellh/go-ps"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// EstBytesPerLine Estimated number of bytes per line - for log rotation
var EstBytesPerLine int = 150

var (
	linesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_officer_lines_processed",
		Help: "Number of access log lines processed",
	})

	linesIgnored = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_officer_lines_ignored",
		Help: "Number of access log lines ignored from latency metrics",
	})

	latencyMetrics = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "traefik_officer_latency",
		Help:    "Latency metrics per service / endpoint",
		Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500, 1000},
	},
		[]string{"RequestPath", "RequestMethod"})
)

type traefikOfficerConfig struct {
	IgnoredNamespaces        []string `json:"IgnoredNamespaces"`
	IgnoredRouters           []string `json:"IgnoredRouters"`
	IgnoredPathsRegex        []string `json:"IgnoredPathsRegex"`
	MergePathsWithExtensions []string `json:"MergePathsWithExtensions"`
	WhitelistPaths           []string `json:"WhitelistPaths"`
}

func main() {
	fileNamePtr := flag.String("log-file", "./accessLog.txt", "The traefik access log file. Default: ./accessLog.txt")
	requestArgsPtr := flag.Bool("include-query-args", false,
		"Set this if you wish for the query arguments to be displayed in the 'RequestPath' in latency metrics. Default: false")
	configLocationPtr := flag.String("config-file", "", "Path to the config file.")
	servePortPtr := flag.String("listen-port", "8080", "Which port to expose metrics on")
	maxFileBytesPtr := flag.Int("max-accesslog-size", 10,
		"How many megabytes should we allow the accesslog to grow to before rotating")
	strictWhiteListPtr := flag.Bool("strict-whitelist", false,
		"If true, ONLY patterns matching the whitelist will be counted. If false, patterns whitelisted just skip ignore rules")
	passLogAboveThresholdPtr := flag.Float64("pass-log-above-threshold", 1,
		"Passthrough traefik accessLog line to stdout if request takes longer that X seconds. Only whitelisted request paths.")
	flag.Parse()

	fmt.Println("Access Logs At:", *fileNamePtr)
	fmt.Println("Config File At:", *configLocationPtr)
	fmt.Println("Display Query Args In Metrics: ", *requestArgsPtr)
	config, _ := loadConfig(*configLocationPtr)
	go serveProm(*servePortPtr)

	linesToRotate := (1000000 * *maxFileBytesPtr) / EstBytesPerLine
	fmt.Printf("Rotating logs every %s lines\n", strconv.Itoa(linesToRotate))

	fmt.Printf("Ignoring Namespaces: %s \nIgnoring Routers: %s\n Ignoring Paths: %s \n Merging Paths: %s\n Whitelist: %s\n",
		config.IgnoredNamespaces, config.IgnoredRouters, config.IgnoredPathsRegex, config.MergePathsWithExtensions,
		config.WhitelistPaths)

	tCfg := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true,
	}

	fmt.Printf("Opening file\n")
	t, err := tail.TailFile(*fileNamePtr, tCfg)
	for {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Starting read\n")
		i := 0
		for line := range t.Lines {
			i++
			if i >= linesToRotate {
				i = 0
				logRotate(*fileNamePtr)
				fmt.Println("Rotated Access Log")
			}
			d, err := parseLine(line.Text)
			if err != nil && err.Error() == "ParseError" {
				fmt.Printf("Parse error for: \n  %s", line.Text)
				continue
			}

			// Push metrics to prometheus exporter
			linesProcessed.Inc()
			latencyStr := strings.Trim(d["Duration"], "ms")
			latency, err := strconv.ParseFloat(latencyStr, 64)
			if err != nil {
				// HTTP Errors turn up here for now
				fmt.Printf("Error converting %s to float\n", latencyStr)
				fmt.Printf("From Line: %s\n\n", line)
			}

			requestPath := d["RequestPath"]
			if *requestArgsPtr == false {
				requestPath = strings.Split(d["RequestPath"], "?")[0]
				requestPath = strings.Split(requestPath, "&")[0]

				// Merge paths where query args are embedded in url (/api/arg1/arg1)
				requestPath = mergePaths(requestPath, config.MergePathsWithExtensions)
			}
			routerName := strings.Trim(d["RouterName"], "\\\"")

			// Check whether path is in the whitelist:
			isWhitelisted := checkWhiteList(requestPath, config.WhitelistPaths)

			if !isWhitelisted && *strictWhiteListPtr {
				linesIgnored.Inc()
				continue
			}
			if !isWhitelisted {
				// Check whether routername matches ignored namespace, router or path regex.
				ignoreMatched := (checkMatches(routerName, config.IgnoredNamespaces) ||
					checkMatches(routerName, config.IgnoredRouters) || checkMatches(requestPath, config.IgnoredPathsRegex))

				if ignoreMatched {
					linesIgnored.Inc()
					continue
				}
			}

			if latency > *passLogAboveThresholdPtr && isWhitelisted {
				fmt.Println(line.Text)
			}

			// Not ignored, publish metric
			latencyMetrics.WithLabelValues(requestPath, d["RequestMethod"]).Observe(latency)
		}
	}
}

func checkWhiteList(str string, matchStrings []string) bool {
	for i := 0; i < len(matchStrings); i++ {
		matchStr := matchStrings[i]
		if strings.Contains(str, matchStr) {
			return true
		}
	}
	return false
}

func mergePaths(str string, matchStrings []string) string {
	for i := 0; i < len(matchStrings); i++ {
		matchStr := matchStrings[i]
		if strings.HasPrefix(str, matchStr) {
			return matchStr
		}
	}
	return str
}

func checkMatches(str string, matchExpressions []string) bool {
	for i := 0; i < len(matchExpressions); i++ {
		expr := matchExpressions[i]
		reg, err := regexp.Compile(expr)

		if err != nil {
			fmt.Printf("Error compiling regex: %s \n", expr)
		}

		if reg.MatchString(str) {
			return true
		}
	}
	return false
}

func parseJSON(line string) (map[string]string, error) {

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

func loadConfig(configLocation string) (traefikOfficerConfig, error) {
	cfgFile, err := os.Open(configLocation)
	if err != nil {
		fmt.Printf("Error opening config file: %s", configLocation)
		var emptyConf traefikOfficerConfig
		return emptyConf, err
	}
	defer cfgFile.Close()
	var config traefikOfficerConfig

	byteValue, err := ioutil.ReadAll(cfgFile)
	if err != nil {
		fmt.Printf("Failed to read config file\n")
	}

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		fmt.Println(err)
	}
	return config, nil
}

func logRotate(accessLogLocation string) {
	processList, err := ps.Processes()
	if err != nil {
		log.Println("ps.Processes() Failed, are you using windows?")
		return
	}

	traefikPid := -1
	for x := range processList {
		var process ps.Process
		process = processList[x]
		if process.Executable() == "traefik" {
			traefikPid = process.Pid()
		}
	}

	if traefikPid == -1 {
		fmt.Printf("Could not find traefik process - not rotating!\n")
		return
	}

	fmt.Printf("Found traefik process @ PID %s\n", strconv.Itoa(traefikPid))

	traefikProcess, err := os.FindProcess(traefikPid)
	if err != nil {
		fmt.Printf("Could not find process with PID process - Not rotating!")
		return
	}

	deleteFile(accessLogLocation)
	createFile(accessLogLocation)

	// Tells traefik to reload the file it's writing to.
	traefikProcess.Signal(syscall.SIGUSR1)

}

func createFile(path string) {
	// check if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			return
		}
		file.Close()
	}
}

func deleteFile(path string) {
	// delete file
	var err = os.Remove(path)
	if err != nil {
		fmt.Printf("Deleting accessLog failed.\n")
		return
	}
}

func serveProm(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":"+port, nil)
}
