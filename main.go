package main

import (
	"context"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Signature represents attack patterns
type Signature struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
}

type IPStats struct {
	IP           string    `json:"ip"`
	RequestCount int       `json:"request_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// TrafficStats holds request count and last-seen time for each IP
type TrafficStats struct {
	RequestCount int
	LastSeen     time.Time
	IsAnomaly    bool
	IsIntrusion  bool
}

// CaddyLog represents the structure of Caddy's JSON log
type CaddyLog struct {
	Timestamp  string `json:"ts"`
	RemoteAddr string `json:"remote_ip"`
	Method     string `json:"method"`
	URI        string `json:"uri"`
	UserAgent  string `json:"user_agent"`
	Status     int    `json:"status"`
}

var (
	trafficData        = make(map[string]*TrafficStats)
	mutex              = &sync.Mutex{}
	signatures         []Signature
	totalRequests      int
	detectedIntrusions int
	detectedAnomalies  int
	statsMutex         sync.Mutex
)

// Load signatures from a JSON file
func loadSignatures(filePath string) ([]Signature, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var sigs []Signature
	if err := json.Unmarshal(data, &sigs); err != nil {
		return nil, err
	}

	return sigs, nil
}

// Check if the request matches any signature
func checkSignatures(logEntry CaddyLog) []Signature {
	var matched []Signature
	for _, sig := range signatures {
		for _, pattern := range sig.Patterns {
			if strings.Contains(logEntry.URI, pattern) || strings.Contains(logEntry.UserAgent, pattern) {
				matched = append(matched, sig)
				break
			}
		}
	}
	return matched
}

// Record request from an IP address for anomaly detection
func recordRequest(ip string) {
	mutex.Lock()
	defer mutex.Unlock()

	stats, exists := trafficData[ip]
	if !exists {
		trafficData[ip] = &TrafficStats{
			RequestCount: 1,
			LastSeen:     time.Now(),
		}
	} else {
		stats.RequestCount++
		stats.LastSeen = time.Now()
	}
}

// Detect anomalies (e.g., too many requests in a short time)
func detectAnomalies(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()

	stats, exists := trafficData[ip]
	if !exists {
		return false
	}

	// Example: more than 100 requests in the last minute
	if stats.RequestCount > 100 && time.Since(stats.LastSeen) < time.Minute {
		return true
	}
	return false
}

// Handle detected intrusion
func handleIntrusion(logEntry CaddyLog, matchedSignatures []Signature) {
	log.Printf("Intrusion detected from %s: %v", logEntry.RemoteAddr, matchedSignatures)
	// TODO: Trigger alert (e.g., send email/SMS or block the IP in Caddy)
}

// Handle detected anomaly
func handleAnomaly(logEntry CaddyLog) {
	log.Printf("Anomaly detected from %s", logEntry.RemoteAddr)
	// TODO: Trigger alert (e.g., rate limiting, temporary blocking)
}

// Process a log entry
func processLogEntry(logEntry CaddyLog) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	totalRequests++

	// Signature-Based Detection
	matchedSignatures := checkSignatures(logEntry)
	if len(matchedSignatures) > 0 {
		handleIntrusion(logEntry, matchedSignatures)
		detectedIntrusions++
		stats, exists := trafficData[logEntry.RemoteAddr]
		if exists {
			stats.IsIntrusion = true
		}
	}

	// Anomaly-Based Detection
	recordRequest(logEntry.RemoteAddr)
	if detectAnomalies(logEntry.RemoteAddr) {
		handleAnomaly(logEntry)
		detectedAnomalies++
		stats, exists := trafficData[logEntry.RemoteAddr]
		if exists {
			stats.IsAnomaly = true
		}
	}
}

// HTTP handler for receiving log entries
func logHandler(w http.ResponseWriter, r *http.Request) {
	var logEntries []CaddyLog // Use a slice to accept an array of CaddyLog entries

	// Read and print the incoming JSON payload for debugging
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	log.Printf("Received payload: %s", body)

	// Decode the JSON into a slice of CaddyLog structs
	err = json.Unmarshal(body, &logEntries)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		log.Printf("JSON Unmarshal error: %v", err)
		return
	}

	// Process each log entry in the array
	for _, logEntry := range logEntries {
		processLogEntry(logEntry)
	}

	w.WriteHeader(http.StatusOK)
}

type IPStat struct {
	IP           string    `json:"ip"`
	RequestCount int       `json:"request_count"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	ipStats := make([]IPStat, 0, len(trafficData))
	for ip, data := range trafficData {
		status := "Normal"
		if data.IsAnomaly {
			status = "Anomaly"
		}
		if data.IsIntrusion {
			status = "Intrusion"
		}
		ipStats = append(ipStats, IPStat{
			IP:           ip,
			RequestCount: data.RequestCount,
			LastSeen:     data.LastSeen,
			Status:       status,
		})
	}

	response := map[string]interface{}{
		"totalRequests":      totalRequests,
		"detectedIntrusions": detectedIntrusions,
		"detectedAnomalies":  detectedAnomalies,
		"ipStats":            ipStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func main() {
	var err error
	signatures, err = loadSignatures("signatures.json")
	if err != nil {
		log.Fatalf("Error loading signatures: %v", err)
	}

	server := &http.Server{Addr: ":3000"}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/logs", logHandler)
	http.HandleFunc("/stats", statsHandler)

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	go func() {
		log.Println("Starting IDS HTTP server on port 3000...")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error starting HTTP server: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exiting")
}
