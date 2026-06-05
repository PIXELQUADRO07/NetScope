package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
}

func apiMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		apiKey := os.Getenv("SCANNER_API_KEY")
		if apiKey != "" {
			// check Authorization: Bearer <key> or X-API-Key
			token := ""
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
				token = strings.TrimSpace(token)
			}
			if token == "" {
				token = r.Header.Get("X-API-Key")
			}
			if token == "" || token != apiKey {
				w.WriteHeader(http.StatusUnauthorized)
				writeJSON(w, map[string]string{"error": "unauthorized"})
				return
			}
		}

		next(w, r)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := "web" + strings.TrimPrefix(r.URL.Path, "/static")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}

func handleAPILocalScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	concurrency := 0
	if v := q.Get("concurrency"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			concurrency = n
		}
	}
	if concurrency == 0 {
		hw, _ := DetectHardware()
		concurrency = hw.MaxRecommended
	}

	hosts, err := ScanLocalNetwork(concurrency)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"hosts": hosts, "count": len(hosts)})
}

func handleAPIASNScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	asn := q.Get("asn")
	concurrency := 0
	if v := q.Get("concurrency"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			concurrency = n
		}
	}
	if concurrency == 0 {
		hw, _ := DetectHardware()
		concurrency = hw.MaxRecommended
	}
	if asn == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "missing asn parameter"})
		return
	}
	hosts, err := ScanTargetASN(asn, concurrency)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"hosts": hosts, "count": len(hosts)})
}

func handleAPIReverse(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "missing ip"})
		return
	}
	names, err := ReverseDNSLookup(ip)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"names": names})
}

func handleAPISSL(w http.ResponseWriter, r *http.Request) {
	h := r.URL.Query().Get("host")
	p := r.URL.Query().Get("port")
	if h == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "missing host"})
		return
	}
	port := 443
	if p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	cert, err := ExtractSSLCertificate(h, port)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, cert)
}

func handleAPICustom(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	portsStr := r.URL.Query().Get("ports")
	if ipStr == "" || portsStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "missing ip or ports"})
		return
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid ip"})
		return
	}
	parts := strings.Split(portsStr, ",")
	ports := []int{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			ports = append(ports, n)
		}
	}
	res := ScanCustomPorts(ip, ports, 10)
	writeJSON(w, res)
}

type PublicSource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Configured  bool   `json:"configured"`
}

func getPublicSources() []PublicSource {
	return []PublicSource{
		{
			ID:          "auto",
			Name:        "Automatico",
			Description: "Seleziona automaticamente il provider pubblico disponibile",
			Configured:  os.Getenv("SHODAN_API_KEY") != "" || (os.Getenv("CENSYS_ID") != "" && os.Getenv("CENSYS_SECRET") != ""),
		},
		{
			ID:          "shodan",
			Name:        "Shodan",
			Description: "Ricerca IP pubblici basata su Shodan",
			Configured:  os.Getenv("SHODAN_API_KEY") != "",
		},
		{
			ID:          "censys",
			Name:        "Censys",
			Description: "Ricerca IP pubblici basata su Censys",
			Configured:  os.Getenv("CENSYS_ID") != "" && os.Getenv("CENSYS_SECRET") != "",
		},
		{
			ID:          "local",
			Name:        "Rete locale",
			Description: "Scansione nella rete locale con filtri disponibili",
			Configured:  true,
		},
	}
}

func buildPublicQuery(source, filter, country, query string) string {
	query = strings.TrimSpace(query)
	filter = strings.TrimSpace(filter)
	country = strings.TrimSpace(country)

	if filter != "" {
		if query != "" {
			query = fmt.Sprintf("%s %s", query, filter)
		} else {
			query = filter
		}
	}

	if country != "" {
		country = strings.ToUpper(country)
		countryField := "country"
		if source == "censys" {
			countryField = "location.country"
		}
		if query != "" {
			query = fmt.Sprintf("%s %s:%s", query, countryField, country)
		} else {
			query = fmt.Sprintf("%s:%s", countryField, country)
		}
	}

	return strings.TrimSpace(query)
}

func handleAPIPublicSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getPublicSources())
}

func handleAPIPublicScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	filter := q.Get("filter")
	country := q.Get("country")
	query := q.Get("query")
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	concurrency := 0
	if v := q.Get("concurrency"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			concurrency = n
		}
	}
	if concurrency == 0 {
		hw, _ := DetectHardware()
		concurrency = hw.MaxRecommended
	}

	if source == "" {
		source = "auto"
	}

	if source == "auto" {
		if os.Getenv("SHODAN_API_KEY") != "" {
			source = "shodan"
		} else if os.Getenv("CENSYS_ID") != "" && os.Getenv("CENSYS_SECRET") != "" {
			source = "censys"
		} else {
			source = "local"
		}
	}

	searchQuery := buildPublicQuery(source, filter, country, query)
	if searchQuery == "" {
		searchQuery = "webcam"
	}

	var hosts []string
	var err error

	switch source {
	case "shodan":
		hosts, err = SearchShodan(searchQuery, os.Getenv("SHODAN_API_KEY"), limit)
	case "censys":
		hosts, err = SearchCensys(searchQuery, os.Getenv("CENSYS_ID"), os.Getenv("CENSYS_SECRET"), limit)
	case "local":
		hosts, err = ScanLocalNetwork(concurrency)
		if err == nil && len(hosts) > limit {
			hosts = hosts[:limit]
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "source sconosciuta"})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{"hosts": hosts, "count": len(hosts), "source": source, "query": searchQuery, "limit": limit})
}

func StartWebServer(addr string) error {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/static/", handleStatic)
	http.HandleFunc("/api/scan/local", apiMiddleware(handleAPILocalScan))
	http.HandleFunc("/api/scan/asn", apiMiddleware(handleAPIASNScan))
	http.HandleFunc("/api/scan/public", apiMiddleware(handleAPIPublicScan))
	http.HandleFunc("/api/sources", apiMiddleware(handleAPIPublicSources))
	http.HandleFunc("/api/reverse", apiMiddleware(handleAPIReverse))
	http.HandleFunc("/api/ssl", apiMiddleware(handleAPISSL))
	http.HandleFunc("/api/custom", apiMiddleware(handleAPICustom))

	srv := &http.Server{
		Addr:         addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second,
	}
	fmt.Printf("Starting web UI on %s\n", addr)
	return srv.ListenAndServe()
}
