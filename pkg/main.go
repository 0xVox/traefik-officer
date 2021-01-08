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
	logger "github.com/sirupsen/logrus"
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

	traefikOverhead = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "traefik_officer_overhead",
		Help: "The overhead caused by traefik processing of requests",
	})

	latencyMetrics = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "traefik_officer_latency",
		Help:    "Latency metrics per service / endpoint",
		Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000},
	},
		[]string{"RequestPath", "RequestMethod"})
)

type parser func(line string) (traefikJSONLog, error)

type traefikOfficerConfig struct {
	IgnoredNamespaces        []string `json:"IgnoredNamespaces"`
	IgnoredRouters           []string `json:"IgnoredRouters"`
	IgnoredPathsRegex        []string `json:"IgnoredPathsRegex"`
	MergePathsWithExtensions []string `json:"MergePathsWithExtensions"`
	WhitelistPaths           []string `json:"WhitelistPaths"`
}

type traefikJSONLog struct {
	ClientHost        string  `json:"ClientHost"`
	StartUTC          string  `json:"StartUTC"`
	RouterName        string  `json:"RouterName"`
	RequestMethod     string  `json:"RequestMethod"`
	RequestPath       string  `json:"RequestPath"`
	RequestProtocol   string  `json:"RequestProtocol"`
	OriginStatus      int     `json:"OriginStatus"`
	OriginContentSize int     `json:"OriginContentSize"`
	RequestCount      int     `json:"RequestCount"`
	Duration          float64 `json:"Duration"`
	Overhead          float64 `json:"Overhead"`
}

func main() {
	debugLogPtr := flag.Bool("debug", false, "Enable debug logging. False by default.")
	fileNamePtr := flag.String("log-file", "./accessLog.txt", "The traefik access log file. Default: ./accessLog.txt")
	requestArgsPtr := flag.Bool("include-query-args", false,
		"Set this if you wish for the query arguments to be displayed in the 'RequestPath' in latency metrics. Default: false")
	configLocationPtr := flag.String("config-file", "", "Path to the config file.")
	servePortPtr := flag.String("listen-port", "8080", "Which port to expose metrics on")
	maxFileBytesPtr := flag.Int("max-accesslog-size", 10,
		"How many megabytes should we allow the accesslog to grow to before rotating")
	strictWhiteListPtr := flag.Bool("strict-whitelist", false,
		"If true, ONLY patterns matching the whitelist will be counted. If false, patterns whitelisted just skip ignore rules")
	jsonLogsPtr := flag.Bool("json-logs", false,
		"If true, parse JSON logs instead of accessLog format")
	passLogAboveThresholdPtr := flag.Float64("pass-log-above-threshold", 1,
		"Passthrough traefik accessLog line to stdout if request takes longer that X seconds. Only whitelisted request paths.")
	flag.Parse()

	if *debugLogPtr {
		logger.SetLevel(logger.DebugLevel)
	}

	logger.Info("Access Logs At:", *fileNamePtr)
	logger.Info("Config File At:", *configLocationPtr)
	logger.Info("Display Query Args In Metrics: ", *requestArgsPtr)
	logger.Info("JSON Logs:", *jsonLogsPtr)
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
	var parse parser
	if *jsonLogsPtr {
		logger.Info("Setting parser to JSON")
		parse = func(line string) (traefikJSONLog, error) {
			result, err := parseJSON(line)
			return result, err
		}
	} else {
		parse = func(line string) (traefikJSONLog, error) {
			result, err := parseLine(line)
			return result, err
		}
	}

	logger.Info("Opening file\n")
	t, err := tail.TailFile(*fileNamePtr, tCfg)
	for {
		if err != nil {
			logger.Error(err)
			os.Exit(1)
		}

		logger.Info("Starting read\n")
		i := 0
		for line := range t.Lines {
			i++
			if i >= linesToRotate {
				i = 0
				logRotate(*fileNamePtr)
			}
			logger.Debugf("Read Line: %s", line.Text)
			d, err := parse(line.Text)
			if err != nil && err.Error() == "ParseError" {
				logger.Error("Parse error for: \n  %s", line.Text)
				continue
			}

			// Push metrics to prometheus exporter
			linesProcessed.Inc()

			requestPath := d.RequestPath
			if *requestArgsPtr == false {
				logger.Debug("Trimming query arguments")
				requestPath = strings.Split(d.RequestPath, "?")[0]
				requestPath = strings.Split(requestPath, "&")[0]

				// Merge paths where query args are embedded in url (/api/arg1/arg1)
				requestPath = mergePaths(requestPath, config.MergePathsWithExtensions)
			}

			// Check whether path is in the whitelist:
			isWhitelisted := checkWhiteList(requestPath, config.WhitelistPaths)

			if !isWhitelisted && *strictWhiteListPtr {
				linesIgnored.Inc()
				continue
			}
			if !isWhitelisted {
				// Check whether routername matches ignored namespace, router or path regex.
				ignoreMatched := (checkMatches(d.RouterName, config.IgnoredNamespaces) ||
					checkMatches(d.RouterName, config.IgnoredRouters) || checkMatches(requestPath, config.IgnoredPathsRegex))

				if ignoreMatched {
					linesIgnored.Inc()
					continue
				}
			}

			if d.Duration > *passLogAboveThresholdPtr && isWhitelisted {
				fmt.Println(line.Text)
			}

			// Not ignored, publish metric
			latencyMetrics.WithLabelValues(requestPath, d.RequestMethod).Observe(d.Duration)

			// Only JSON logs have Overhead metrics
			if *jsonLogsPtr {
				traefikOverhead.Observe(d.Overhead)
			}
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
			logger.Error("Error compiling regex: %s \n", expr)
		}

		if reg.MatchString(str) {
			return true
		}
	}
	return false
}

func parseJSON(line string) (traefikJSONLog, error) {
	var log traefikJSONLog
	var jsonValid bool
	jsonValid = json.Valid([]byte(line))

	if !jsonValid {
		err := errors.New("JSON Log line invalid")
		logger.Errorf("%s '%s'", err, line)
	}

	err := json.Unmarshal([]byte(line), &log)
	if err != nil {
		logger.Error(err)
	}

	log.Duration = log.Duration / 1000000 // JSON Logs format latency in nanoseconds, convert to ms
	log.Overhead = log.Overhead / 1000000 // sane for overhead metrics

	logger.Debugf("JSON Parsed: %s", log)
	logger.Debugf("ClientHost: %s", log.ClientHost)
	logger.Debugf("StartUTC: %s", log.StartUTC)
	logger.Debugf("RouterName: %s", log.RouterName)
	logger.Debugf("RequestMethod: %s", log.RequestMethod)
	logger.Debugf("RequestPath: %s", log.RequestPath)
	logger.Debugf("RequestProtocol: %s", log.RequestProtocol)
	logger.Debugf("OriginStatus: %d", log.OriginStatus)
	logger.Debugf("OriginContentSize: %dbytes", log.OriginContentSize)
	logger.Debugf("RequestCount: %d", log.RequestCount)
	logger.Debugf("Duration: %fms", log.Duration)
	logger.Debugf("Overhead: %fms", log.Overhead)

	return log, err
}

func parseLine(line string) (traefikJSONLog, error) {
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
		err = errors.New("ParseError")
	}

	submatch := regex.FindStringSubmatch(line)
	var log traefikJSONLog

	if len(submatch) > 13 {
		log.ClientHost = submatch[1]
		log.StartUTC = submatch[3]
		log.RequestMethod = submatch[4]
		log.RequestPath = submatch[5]
		log.RequestProtocol = submatch[6]
		log.OriginStatus, _ = strconv.Atoi(submatch[7])
		log.OriginContentSize, _ = strconv.Atoi(submatch[8])
		log.RequestCount, _ = strconv.Atoi(submatch[11])
		log.RouterName = strings.Trim(submatch[12], "\\\"")

		latencyStr := strings.Trim(submatch[14], "ms")
		log.Duration, err = strconv.ParseFloat(latencyStr, 64)
		if err != nil {
			logger.Errorf("Error converting %s to int\n", latencyStr)
			logger.Errorf("From Line: %s\n\n", line)
		}

		logger.Debugf("ClientHost: %s", log.ClientHost)
		logger.Debugf("StartUTC: %s", log.StartUTC)
		logger.Debugf("RouterName: %s", log.RouterName)
		logger.Debugf("RequestMethod: %s", log.RequestMethod)
		logger.Debugf("RequestPath: %s", log.RequestPath)
		logger.Debugf("RequestProtocol: %s", log.RequestProtocol)
		logger.Debugf("OriginStatus: %d", log.OriginStatus)
		logger.Debugf("OriginContentSize: %d b", log.OriginContentSize)
		logger.Debugf("RequestCount: %d", log.RequestCount)
		logger.Debugf("Duration: %f ms", log.Duration)

		return log, nil
	}

	logger.Warn("Line not in access log format: %s", line)
	err = errors.New("Access Log Line Invalid")
	return log, err
}

func loadConfig(configLocation string) (traefikOfficerConfig, error) {
	cfgFile, err := os.Open(configLocation)
	if err != nil {
		logger.Errorf("Error opening config file: %s", configLocation)
		var emptyConf traefikOfficerConfig
		return emptyConf, err
	}
	defer cfgFile.Close()
	var config traefikOfficerConfig

	byteValue, err := ioutil.ReadAll(cfgFile)
	if err != nil {
		logger.Error("Failed to read config file\n")
	}

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		logger.Error(err)
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
		logger.Warn("Could not find traefik process - not rotating!\n")
		return
	}

	fmt.Printf("Found traefik process @ PID %s\n", strconv.Itoa(traefikPid))

	traefikProcess, err := os.FindProcess(traefikPid)
	if err != nil {
		logger.Warn("Could not find process with PID process - Not rotating!")
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
		logger.Warn("Deleting accessLog failed.\n")
		return
	}
}

func serveProm(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":"+port, nil)
}
