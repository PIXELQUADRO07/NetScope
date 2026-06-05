package main

import (
	"fmt"
	"os"
	"time"
)

func GenerateHTMLReport(filename string, report ScanReport) error {
	serviceStats := make(map[string]int)
	vulnerabilityCount := 0

	for _, result := range report.Results {
		if result.Banner != "" {
			serviceStats[result.Banner]++
		}
	}

	// Build services list and data
	servicesLabels := ""
	servicesData := ""
	for service, count := range serviceStats {
		servicesLabels += fmt.Sprintf(`'%s',`, service)
		servicesData += fmt.Sprintf(`%d,`, count)
	}

	// Build results table rows
	resultsRows := ""
	for _, result := range report.Results {
		resultsRows += fmt.Sprintf(`                <tr>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s</td>
                </tr>
`, result.IP, result.Banner, result.Timestamp.Format("2006-01-02 15:04:05"))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        h1 { color: #667eea; margin-bottom: 10px; }
        .meta { color: #666; font-size: 14px; }
        .meta span { margin-right: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .stat-value { font-size: 32px; font-weight: bold; color: #667eea; }
        .stat-label { color: #999; font-size: 14px; margin-top: 10px; }
        .chart-container { position: relative; height: 400px; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); margin-bottom: 30px; }
        table { width: 100%%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        th { background: #667eea; color: white; padding: 15px; text-align: left; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f5f5f5; }
        .risk-high { color: #d32f2f; font-weight: bold; }
        .risk-medium { color: #f57c00; font-weight: bold; }
        .risk-low { color: #388e3c; font-weight: bold; }
        footer { text-align: center; color: white; margin-top: 30px; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 NetScope Report</h1>
            <div class="meta">
                <span>📅 Generated: %s</span>
                <span>🎯 Target: %s</span>
                <span>⏱️ Duration: %.1f seconds</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Active Hosts Found</div>
            </div>
            <div class="card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Unique Services</div>
            </div>
            <div class="card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Vulnerabilities Detected</div>
            </div>
        </div>

        <div class="chart-container">
            <canvas id="servicesChart"></canvas>
        </div>

        <h2 style="background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;">Scan Results</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Banner/Service</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
%s            </tbody>
        </table>

        <script>
            const ctx = document.getElementById('servicesChart').getContext('2d');
            const servicesChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: [%s],
                    datasets: [{
                        data: [%s],
                        backgroundColor: [
                            '#667eea',
                            '#764ba2',
                            '#f093fb',
                            '#4facfe',
                            '#00f2fe',
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        },
                        title: {
                            display: true,
                            text: 'Services Distribution'
                        }
                    }
                }
            });
        </script>

        <footer>
            <p>Generated by NetScope | %s</p>
        </footer>
    </div>
</body>
</html>
`,
		time.Now().Format("2006-01-02 15:04:05"),
		report.Target,
		report.EndTime.Sub(report.StartTime).Seconds(),
		report.Total,
		len(serviceStats),
		vulnerabilityCount,
		resultsRows,
		servicesLabels,
		servicesData,
		time.Now().Format(time.RFC1123),
	)

	return os.WriteFile(filename, []byte(html), 0644)
}
