package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"time"
)

type ScanResult struct {
	IP        string    `json:"ip"`
	Banner    string    `json:"banner,omitempty"`
	Ports     []int     `json:"ports,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type ScanReport struct {
	ScanType  string       `json:"scan_type"`
	Target    string       `json:"target"`
	Results   []ScanResult `json:"results"`
	Total     int          `json:"total"`
	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time"`
}

func SaveResultsJSON(filename string, report ScanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func SaveResultsCSV(filename string, results []ScanResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"IP", "Banner", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		record := []string{
			r.IP,
			r.Banner,
			r.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}
