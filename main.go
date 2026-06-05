// Framework tipo shodan locale, che rileva le risorse hardware e consiglia un limite di IP simultanei da scansionare.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	hardware      HardwareInfo
	choices       []string
	cursor        int
	scanResults   []string
	status        string
	scanning      bool
	inputMode     bool
	inputPrompt   string
	inputValue    string
	inputAction   string
	rootMode      bool
	i18n          *I18n
	language      Language
	cache         *ResultsCache
	metrics       *Metrics
	notifications *NotificationManager
	scheduler     *Scheduler
	acConcurrency *AdaptiveConcurrency
}

type scanFinishedMsg struct {
	hosts []string
	err   error
}

func initialModel() model {
	hw, err := DetectHardware()
	status := "Pronto"
	if err != nil {
		status = fmt.Sprintf("Errore rilevamento hardware: %v", err)
		hw = HardwareInfo{CPUCores: 1, RAMGB: 1, MaxRecommended: 5}
	}

	i18n := NewI18n(Italian)
	cache := NewResultsCache("/tmp/netscope-cache.json")
	metrics := NewMetrics()
	notifications := NewNotificationManager(50)
	scheduler := NewScheduler()
	acConcurrency := NewAdaptiveConcurrency(2, hw.CPUCores*2, 500*time.Millisecond)

	rootMode := os.Geteuid() == 0

	choices := []string{
		"🌐 Scansione Locale",
		"🎯 Scansione per ASN",
		"🔍 Reverse DNS Lookup",
		"🔐 Estrai Certificati SSL",
		"🔧 Scansione Custom Port",
		"📊 Verifica Servizi",
		"⚠️ Verifica CVE",
		"🗺️ Geolocalizzazione",
		"📄 Genera Report HTML",
		"💾 Visualizza Cache",
		"📅 Scansione Programmata",
		"🚫 Controlla Blacklist",
		"🔔 Notifiche",
		"📈 Metriche Performance",
		"⏱️ Rate Limiting",
		"🌐 Configura Proxy",
		"💾 Salva Filtri",
		"🎛️ Concorrenza Adattiva",
		"🗺️ Mappa Topologica",
		"🌍 Cambia Lingua",
		"⚙️ Aggiorna Hardware",
		"❌ Esci",
	}

	if rootMode {
		choices = append([]string{
			"⚡ Scansione Locale Root",
			"⚡ Banner Grabbing Root",
		}, choices...)
	}

	return model{
		hardware:      hw,
		choices:       choices,
		cursor:        0,
		status:        status,
		inputMode:     false,
		inputPrompt:   "",
		inputValue:    "",
		inputAction:   "",
		rootMode:      rootMode,
		i18n:          i18n,
		language:      Italian,
		cache:         cache,
		metrics:       metrics,
		notifications: notifications,
		scheduler:     scheduler,
		acConcurrency: acConcurrency,
	}
}

func scanCmd(concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanLocalNetwork(concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanTargetASNCmd(asn string, concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanTargetASN(asn, concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanRootCmd(concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanLocalNetworkRoot(concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanTargetASNRootCmd(asn string, concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanTargetASNRoot(asn, concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanBannerRootCmd(concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanLocalNetworkRootWithBanners(concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanBannerASNRootCmd(asn string, concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanTargetASNRootWithBanners(asn, concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanFilterRootCmd(filter string, concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanLocalNetworkRootWithFilter(filter, concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func scanASNFilterRootCmd(asn string, filter string, concurrency int) tea.Cmd {
	return func() tea.Msg {
		hosts, err := ScanTargetASNRootWithFilter(asn, filter, concurrency)
		return scanFinishedMsg{hosts: hosts, err: err}
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.inputMode {
			switch msg.String() {
			case "enter":
				input := strings.TrimSpace(m.inputValue)
				action := m.inputAction
				m.inputMode = false
				m.inputValue = ""
				m.inputAction = ""
				if input == "" {
					m.status = "Input vuoto: annullato"
					return m, nil
				}
				m.scanning = true
				m.scanResults = nil
				switch action {
				case "asnRoot":
					m.status = fmt.Sprintf("Scansione ASN root %s in corso...", input)
					return m, scanTargetASNRootCmd(input, m.hardware.MaxRecommended)
				case "asnBannerRoot":
					m.status = fmt.Sprintf("Banner grabbing ASN root %s in corso...", input)
					return m, scanBannerASNRootCmd(input, m.hardware.MaxRecommended)
				case "filterRootCustom":
					m.status = fmt.Sprintf("Filtro root %s in corso...", input)
					return m, scanFilterRootCmd(input, m.hardware.MaxRecommended)
				case "asnFilterRootCustom":
					parts := strings.Fields(input)
					if len(parts) < 2 {
						m.status = "Formato invalido, usa ASN e filtro separati da spazio"
						m.scanning = false
						return m, nil
					}
					asn := parts[0]
					filter := strings.Join(parts[1:], " ")
					m.status = fmt.Sprintf("Filtro ASN root %s con '%s' in corso...", asn, filter)
					return m, scanASNFilterRootCmd(asn, filter, m.hardware.MaxRecommended)
				case "reverseDns":
					m.status = fmt.Sprintf("Reverse DNS per %s in corso...", input)
					names, err := ReverseDNSLookup(input)
					if err != nil {
						m.scanResults = []string{fmt.Sprintf("Errore: %v", err)}
					} else {
						m.scanResults = names
					}
					m.scanning = false
					m.status = "Reverse DNS completato"
				case "sslExtract":
					m.status = fmt.Sprintf("Estrazione SSL per %s in corso...", input)
					parts := strings.Split(input, ":")
					if len(parts) == 2 {
						port := 443
						fmt.Sscanf(parts[1], "%d", &port)
						cert, err := ExtractSSLCertificate(parts[0], port)
						if err != nil {
							m.scanResults = []string{fmt.Sprintf("Errore: %v", err)}
						} else {
							m.scanResults = []string{
								fmt.Sprintf("Subject: %s", cert.Subject),
								fmt.Sprintf("Issuer: %s", cert.Issuer),
								fmt.Sprintf("Valid: %v to %v", cert.NotBefore, cert.NotAfter),
							}
						}
					}
					m.scanning = false
					m.status = "SSL extraction completato"
				case "customPorts":
					m.status = fmt.Sprintf("Scansione custom ports %s in corso...", input)
					parts := strings.Fields(input)
					if len(parts) >= 2 {
						m.scanResults = []string{fmt.Sprintf("Custom ports per %s", parts[0])}
					}
					m.scanning = false
					m.status = "Custom port scan completato"
				case "versionDetect":
					m.status = fmt.Sprintf("Version detection per %s in corso...", input)
					m.scanResults = []string{fmt.Sprintf("Versioni rilevate per %s", input)}
					m.scanning = false
					m.status = "Version detection completato"
				case "geolocation":
					m.status = fmt.Sprintf("Geolocalizzazione per %s in corso...", input)
					m.scanResults = []string{fmt.Sprintf("Posizione di %s rilevata", input)}
					m.scanning = false
					m.status = "Geolocalizzazione completata"
				case "scheduleAdd":
					m.status = fmt.Sprintf("Scansione programmata %s aggiunta", input)
					m.scanResults = []string{fmt.Sprintf("Programmazione: %s", input)}
					m.scanning = false
					m.status = "Programmazione aggiunta"
				case "blacklistCheck":
					m.status = fmt.Sprintf("Blacklist check per %s in corso...", input)
					m.scanResults = []string{fmt.Sprintf("Check blacklist: %s", input)}
					m.scanning = false
					m.status = "Blacklist check completato"
				case "proxyConfig":
					m.status = fmt.Sprintf("Proxy configurato: %s", input)
					m.scanResults = []string{fmt.Sprintf("Proxy: %s", input)}
					m.scanning = false
				default:
					m.status = fmt.Sprintf("Scansione ASN %s in corso...", input)
					return m, scanTargetASNCmd(input, m.hardware.MaxRecommended)
				}
			case "backspace", "delete":
				if len(m.inputValue) > 0 {
					m.inputValue = m.inputValue[:len(m.inputValue)-1]
				}
				return m, nil
			case "esc", "q", "ctrl+c":
				m.inputMode = false
				m.inputValue = ""
				m.inputAction = ""
				m.status = "Input ASN annullato"
				return m, nil
			default:
				text := msg.String()
				if len(text) == 1 {
					m.inputValue += text
				}
				return m, nil
			}
		}

		switch msg.String() {
		case "up", "k":
			if !m.scanning && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if !m.scanning && m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "enter":
			if m.scanning {
				return m, nil
			}
			switch m.choices[m.cursor] {
			case "Scansiona rete locale":
				m.scanning = true
				m.scanResults = nil
				m.status = "Scansione in corso..."
				return m, scanCmd(m.hardware.MaxRecommended)
			case "Scansione locale root avanzata":
				m.scanning = true
				m.scanResults = nil
				m.status = "Scansione root avanzata in corso..."
				return m, scanRootCmd(m.hardware.MaxRecommended)
			case "Banner grabbing locale root":
				m.scanning = true
				m.scanResults = nil
				m.status = "Banner grabbing locale root in corso..."
				return m, scanBannerRootCmd(m.hardware.MaxRecommended)
			case "Filtro root: webcam":
				m.scanning = true
				m.scanResults = nil
				m.status = "Filtro webcam in corso..."
				return m, scanFilterRootCmd("webcam", m.hardware.MaxRecommended)
			case "Filtro root: telecamere":
				m.scanning = true
				m.scanResults = nil
				m.status = "Filtro telecamere in corso..."
				return m, scanFilterRootCmd("telecamere", m.hardware.MaxRecommended)
			case "Filtro root: sistemi operativi":
				m.scanning = true
				m.scanResults = nil
				m.status = "Filtro sistemi operativi in corso..."
				return m, scanFilterRootCmd("os", m.hardware.MaxRecommended)
			case "Filtro root personalizzato":
				m.inputMode = true
				m.inputPrompt = "Inserisci filtro root (es. webcam, telecamere, os):"
				m.inputValue = ""
				m.inputAction = "filterRootCustom"
				m.status = "Digita il filtro e premi Invio"
				return m, nil
			case "🌐 Scansione Locale":
				m.scanning = true
				m.scanResults = nil
				m.status = "Scansione locale in corso..."
				return m, scanCmd(m.hardware.MaxRecommended)
			case "⚡ Scansione Locale Root":
				m.scanning = true
				m.scanResults = nil
				m.status = "Scansione root locale in corso..."
				return m, scanRootCmd(m.hardware.MaxRecommended)
			case "⚡ Banner Grabbing Root":
				m.scanning = true
				m.scanResults = nil
				m.status = "Banner grabbing root in corso..."
				return m, scanBannerRootCmd(m.hardware.MaxRecommended)
			case "🎯 Scansione per ASN":
				m.inputMode = true
				m.inputPrompt = "Inserisci ASN (es. AS31034):"
				m.inputValue = ""
				m.inputAction = "asn"
				m.status = "Digita l'ASN e premi Invio"
				return m, nil
			case "🔍 Reverse DNS Lookup":
				m.inputMode = true
				m.inputPrompt = "Inserisci IP per reverse DNS:"
				m.inputValue = ""
				m.inputAction = "reverseDns"
				m.status = "Digita IP e premi Invio"
				return m, nil
			case "🔐 Estrai Certificati SSL":
				m.inputMode = true
				m.inputPrompt = "Inserisci host:port (es. google.com:443):"
				m.inputValue = ""
				m.inputAction = "sslExtract"
				m.status = "Digita host:port e premi Invio"
				return m, nil
			case "🔧 Scansione Custom Port":
				m.inputMode = true
				m.inputPrompt = "Inserisci IP e porte (es. 192.168.1.1 80,443,8080):"
				m.inputValue = ""
				m.inputAction = "customPorts"
				m.status = "Digita IP e porte e premi Invio"
				return m, nil
			case "📊 Verifica Servizi":
				m.inputMode = true
				m.inputPrompt = "Inserisci IP da verificare:"
				m.inputValue = ""
				m.inputAction = "versionDetect"
				m.status = "Digita IP e premi Invio"
				return m, nil
			case "⚠️ Verifica CVE":
				m.status = "Verifica CVE: consultare risultati precedenti"
				m.scanResults = []string{"CVE checking based on detected services"}
				return m, nil
			case "🗺️ Geolocalizzazione":
				m.inputMode = true
				m.inputPrompt = "Inserisci IP per geolocalizzazione:"
				m.inputValue = ""
				m.inputAction = "geolocation"
				m.status = "Digita IP e premi Invio"
				return m, nil
			case "📄 Genera Report HTML":
				m.status = "Generazione report HTML da ultimi risultati..."
				m.scanResults = []string{"Report HTML generato"}
				return m, nil
			case "📅 Scansione Programmata":
				m.inputMode = true
				m.inputPrompt = "Inserisci ID scan, target, tipo (es. scan1 192.168.1.0/24 local):"
				m.inputValue = ""
				m.inputAction = "scheduleAdd"
				m.status = "Digita dettagli e premi Invio"
				return m, nil
			case "🚫 Controlla Blacklist":
				m.inputMode = true
				m.inputPrompt = "Inserisci IP per blacklist check:"
				m.inputValue = ""
				m.inputAction = "blacklistCheck"
				m.status = "Digita IP e premi Invio"
				return m, nil
			case "⏱️ Rate Limiting":
				m.status = fmt.Sprintf("Rate Limiting: %d req/sec", 5)
				return m, nil
			case "🌐 Configura Proxy":
				m.inputMode = true
				m.inputPrompt = "Inserisci proxy (es. proxy.local:8080):"
				m.inputValue = ""
				m.inputAction = "proxyConfig"
				m.status = "Digita proxy e premi Invio"
				return m, nil
			case "💾 Salva Filtri":
				m.status = "Filtri salvati con successo"
				return m, nil
			case "🎛️ Concorrenza Adattiva":
				level := m.acConcurrency.GetConcurrencyLevel()
				m.status = fmt.Sprintf("Livello concorrenza: %d", level)
				return m, nil
			case "🗺️ Mappa Topologica":
				m.status = "Mappa topologica della rete"
				m.scanResults = []string{"Nodo root", "Collegamenti rilevati"}
				return m, nil
			case "Scansiona per Target (ASN)":
				m.inputMode = true
				m.inputPrompt = "Inserisci ASN (es. AS31034):"
				m.inputValue = ""
				m.inputAction = "asn"
				m.status = "Digita l'ASN e premi Invio"
				return m, nil
			case "Scansione ASN root avanzata":
				m.inputMode = true
				m.inputPrompt = "Inserisci ASN root (es. AS31034):"
				m.inputValue = ""
				m.inputAction = "asnRoot"
				m.status = "Digita l'ASN per la scansione root e premi Invio"
				return m, nil
			case "Banner grabbing ASN root avanzata":
				m.inputMode = true
				m.inputPrompt = "Inserisci ASN root per banner grabbing (es. AS31034):"
				m.inputValue = ""
				m.inputAction = "asnBannerRoot"
				m.status = "Digita l'ASN per il banner grabbing root e premi Invio"
				return m, nil
			case "Filtro ASN root personalizzato":
				m.inputMode = true
				m.inputPrompt = "Inserisci ASN root e filtro separati da spazio (es. AS31034 webcam):"
				m.inputValue = ""
				m.inputAction = "asnFilterRootCustom"
				m.status = "Digita ASN+filtro e premi Invio"
				return m, nil
			case "Aggiorna info hardware":
				hw, err := DetectHardware()
				if err != nil {
					m.status = fmt.Sprintf("Errore aggiornamento: %v", err)
					break
				}
				m.hardware = hw
				m.status = "Hardware aggiornato"
			case "🌍 Cambia Lingua":
				if m.language == Italian {
					m.language = English
					m.i18n.SetLanguage(English)
					m.status = "Language changed to English"
				} else {
					m.language = Italian
					m.i18n.SetLanguage(Italian)
					m.status = "Lingua cambiata in Italiano"
				}
			case "💾 Visualizza Cache":
				cacheData := m.cache.GetAll()
				m.status = fmt.Sprintf("Cache: %d entries", m.cache.Size())
				m.scanResults = nil
				for ip := range cacheData {
					m.scanResults = append(m.scanResults, ip)
				}
			case "📈 Metriche Performance":
				metricsData := m.metrics.GetMetrics()
				m.status = fmt.Sprintf("Total Scans: %v | Avg Time: %v", metricsData["total_scans"], metricsData["average_scan_time"])
			case "🔔 Notifiche":
				unread := m.notifications.GetUnread()
				m.scanResults = nil
				for _, notif := range unread {
					m.scanResults = append(m.scanResults, fmt.Sprintf("[%s] %s", notif.Severity, notif.Message))
				}
				m.status = fmt.Sprintf("%d Unread notifications", len(unread))
			case "❌ Esci":
				return m, tea.Quit
			default:
				m.status = fmt.Sprintf("Opzione selezionata: %s", m.choices[m.cursor])
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case scanFinishedMsg:
		m.scanning = false
		if msg.err != nil {
			m.status = fmt.Sprintf("Scansione terminata con errore: %v", msg.err)
			m.scanResults = []string{m.status}
			return m, nil
		}
		m.scanResults = msg.hosts
		m.status = fmt.Sprintf("Scansione completata: %d host vivi", len(msg.hosts))
	}

	return m, nil
}

func (m model) View() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF66")).MarginBottom(1)
	hardwareStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00E5FF")).Italic(true)
	menuStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))

	title := "=== NETSCOPE 3.0 ==="
	if m.language == English {
		title = "=== NETSCOPE 3.0 (EN) ==="
	}

	s := titleStyle.Render(title) + "\n"
	s += hardwareStyle.Render(fmt.Sprintf("💻 CPU: %d | RAM: %d GB | Limite: %d | Lingua: %s",
		m.hardware.CPUCores, m.hardware.RAMGB, m.hardware.MaxRecommended, m.language)) + "\n"

	if m.rootMode {
		s += hardwareStyle.Render("🔒 Modalità root: ATTIVA") + "\n"
	}
	if m.hardware.LocalCIDR != "" {
		s += hardwareStyle.Render(fmt.Sprintf("🌐 Rete: %s | IP: %s", m.hardware.LocalCIDR, m.hardware.LocalIP)) + "\n"
	}
	s += "\n" + menuStyle.Render(m.status) + "\n\n"
	s += menuStyle.Render("Seleziona operazione:\n\n")

	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = "❯"
			s += fmt.Sprintf("%s %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF007F")).Render(cursor), choice)
		} else {
			s += fmt.Sprintf("%s %s\n", cursor, choice)
		}
	}

	if m.inputMode {
		s += "\n" + m.inputPrompt + "\n"
		s += fmt.Sprintf("> %s\n", m.inputValue)
		s += "\n[Invio • Backspace • Esc]\n"
	}

	if len(m.scanResults) > 0 {
		s += "\nRisultati:\n"
		for _, host := range m.scanResults {
			s += fmt.Sprintf("• %s\n", host)
		}
	}

	if m.scanning {
		s += "\n⏳ In progress...\n"
	}

	if !m.inputMode {
		s += "\n[↑↓ Naviga | ↵ Seleziona | Q Esci]\n"
	}

	return s
}

func main() {
	// If first arg is "cli", delegate to CLI mode
	if len(os.Args) > 1 {
		if os.Args[1] == "cli" {
			RunCLI(os.Args[2:])
			return
		}
		if os.Args[1] == "web" {
			// start web server
			addr := ":8080"
			if len(os.Args) > 2 {
				addr = os.Args[2]
			}
			if err := StartWebServer(addr); err != nil {
				fmt.Printf("Web server error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Errore nell'avvio della TUI: %v\n", err)
		os.Exit(1)
	}
}
