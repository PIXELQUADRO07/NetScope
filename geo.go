package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ASNGeoInfo struct {
	ASN         int     `json:"asn"`
	Name        string  `json:"name"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Type        string  `json:"type"`
}

type IPStackResponse struct {
	IP           string  `json:"ip"`
	Continent    string  `json:"continent_name"`
	Country      string  `json:"country_name"`
	CountryCode  string  `json:"country_code"`
	Region       string  `json:"region_name"`
	City         string  `json:"city"`
	Timezone     string  `json:"time_zone"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"connection.isp"`
	Organization string  `json:"connection.organization_name"`
	ASN          int     `json:"connection.asn"`
}

func GetASNGeoLocation(asn string, token string) (*ASNGeoInfo, error) {
	if token == "" {
		return nil, fmt.Errorf("token IPStack non configurato")
	}

	url := fmt.Sprintf("https://api.asnlookup.com/api/lookup?asn=%s", asn)
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ASN lookup fallito: %s", resp.Status)
	}

	var result ASNGeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func GetIPGeoLocation(ip string, token string) (*IPStackResponse, error) {
	if token == "" {
		return nil, fmt.Errorf("token IPStack non configurato")
	}

	url := fmt.Sprintf("http://api.ipstack.com/%s?access_key=%s&format=json", ip, token)
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IP geolocalizzazione fallita: %s", resp.Status)
	}

	var result IPStackResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func FormatGeoLocation(geoInfo *IPStackResponse) string {
	if geoInfo == nil {
		return "Geolocalizzazione non disponibile"
	}
	return fmt.Sprintf("%s, %s (%.2f, %.2f)", geoInfo.City, geoInfo.Country, geoInfo.Latitude, geoInfo.Longitude)
}
