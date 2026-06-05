package main

import (
	"fmt"
)

type Language string

const (
	Italian Language = "it"
	English Language = "en"
)

type Translations map[string]map[Language]string

var messages = Translations{
	"menu_title":            {Italian: "📡 NetScope", English: "📡 NetScope"},
	"menu_subtitle":         {Italian: "Scanner di rete avanzato", English: "Advanced Network Scanner"},
	"menu_choose_action":    {Italian: "Scegli un'azione:", English: "Choose an action:"},
	"scan_local":            {Italian: "Scansione locale /24", English: "Local Scan /24"},
	"scan_local_root":       {Italian: "Scansione root /24", English: "Root Scan /24"},
	"scan_local_banners":    {Italian: "Scansione banner (root)", English: "Banner Scan (root)"},
	"scan_asn":              {Italian: "Scansione per ASN", English: "Scan by ASN"},
	"scan_ipv6":             {Italian: "Scansione IPv6 /64", English: "IPv6 Scan /64"},
	"dns_reverse":           {Italian: "Reverse DNS Lookup", English: "Reverse DNS Lookup"},
	"ssl_extract":           {Italian: "Estrai Certificati SSL", English: "Extract SSL Certificates"},
	"custom_ports":          {Italian: "Scansione Custom Port", English: "Custom Port Scan"},
	"service_version":       {Italian: "Rileva Versioni Servizi", English: "Service Version Detection"},
	"cve_check":             {Italian: "Verifica CVE", English: "CVE Check"},
	"geolocation":           {Italian: "Geolocalizzazione", English: "Geolocation"},
	"html_report":           {Italian: "Genera Report HTML", English: "Generate HTML Report"},
	"cache_view":            {Italian: "Visualizza Cache", English: "View Cache"},
	"schedule_scan":         {Italian: "Scansione Programmata", English: "Scheduled Scan"},
	"blacklist_check":       {Italian: "Controlla Blacklist", English: "Blacklist Check"},
	"notifications":         {Italian: "Notifiche", English: "Notifications"},
	"performance_metrics":   {Italian: "Metriche di Performance", English: "Performance Metrics"},
	"rate_limiting":         {Italian: "Rate Limiting", English: "Rate Limiting"},
	"proxy_config":          {Italian: "Configura Proxy", English: "Configure Proxy"},
	"filter_save":           {Italian: "Salva Filtri", English: "Save Filters"},
	"adaptive_concurrency":  {Italian: "Concorrenza Adattiva", English: "Adaptive Concurrency"},
	"topology_map":          {Italian: "Mappa Topologica", English: "Topology Map"},
	"exit":                  {Italian: "Esci", English: "Exit"},
	"status_running":        {Italian: "Scansione in corso...", English: "Scanning..."},
	"status_complete":       {Italian: "Scansione completata!", English: "Scan completed!"},
	"enter_ip":              {Italian: "Inserisci IP: ", English: "Enter IP: "},
	"enter_asn":             {Italian: "Inserisci ASN: ", English: "Enter ASN: "},
	"enter_ports":           {Italian: "Inserisci porte (es: 80,443,8080): ", English: "Enter ports (e.g., 80,443,8080): "},
	"error_title":           {Italian: "Errore", English: "Error"},
	"success_title":         {Italian: "Successo", English: "Success"},
	"cpu_cores":             {Italian: "Core CPU", English: "CPU Cores"},
	"ram_gb":                {Italian: "RAM (GB)", English: "RAM (GB)"},
	"local_network":         {Italian: "Rete Locale", English: "Local Network"},
	"results":               {Italian: "Risultati", English: "Results"},
	"hosts_found":           {Italian: "Host trovati", English: "Hosts found"},
	"services_detected":     {Italian: "Servizi rilevati", English: "Services detected"},
	"vulnerabilities_found": {Italian: "Vulnerabilità trovate", English: "Vulnerabilities found"},
	"cached_results":        {Italian: "Risultati in cache", English: "Cached results"},
	"no_results":            {Italian: "Nessun risultato", English: "No results"},
	"language_it":           {Italian: "Italiano", English: "Italian"},
	"language_en":           {Italian: "English", English: "English"},
	"select_language":       {Italian: "Seleziona lingua:", English: "Select language:"},
}

type I18n struct {
	language Language
}

func NewI18n(lang Language) *I18n {
	return &I18n{language: lang}
}

func (i *I18n) T(key string) string {
	if trans, exists := messages[key]; exists {
		if text, hasLang := trans[i.language]; hasLang {
			return text
		}
		// Fallback to English
		if text, hasLang := trans[English]; hasLang {
			return text
		}
	}
	return fmt.Sprintf("MISSING: %s", key)
}

func (i *I18n) Tf(key string, args ...interface{}) string {
	return fmt.Sprintf(i.T(key), args...)
}

func (i *I18n) SetLanguage(lang Language) {
	i.language = lang
}

func (i *I18n) GetLanguage() Language {
	return i.language
}

// Pluralization support
func (i *I18n) Plural(key string, count int) string {
	text := i.T(key)
	if count == 1 {
		return fmt.Sprintf("%s (%d)", text, count)
	}
	return fmt.Sprintf("%s (%d)", text, count)
}
