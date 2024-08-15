package storage

import (
	"encoding/json"
	"fmt"
	"fyp/models"
	"io"
	"net/http"
	"net/url"
	"time"
)

func GetLogs() (*models.Log, error){
	u, err := url.Parse("http://localhost:9000")
	if err != nil {
		fmt.Println(err)
	}

	query := "SELECT * FROM logs ORDER BY timestamp DESC "
	// query := "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100"
	
	u.Path += "exec"
	params := url.Values{}
	params.Add("query", query)
	u.RawQuery = params.Encode()
	url := fmt.Sprintf("%v", u)

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var logData models.Log
	if err := json.Unmarshal(body, &logData); err != nil {
		return nil, err
	}

	return &logData, nil
}

func GetLog(logID string) (*models.Log, error){
	u, err := url.Parse("http://localhost:9000")
	if err != nil {
		fmt.Println(err)
	}

	query := "SELECT * FROM logs WHERE logID = '" + logID + "'"

	u.Path += "exec"
	params := url.Values{}
	params.Add("query", query)
	u.RawQuery = params.Encode()
	url := fmt.Sprintf("%v", u)

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var logData models.Log
	if err := json.Unmarshal(body, &logData); err != nil {
		return nil, err
	}

	return &logData, nil
}

type LogData struct {
	Dataset [][]interface{} `json:"dataset"`
}

func executeQuery(query string) ([][]interface{}, error) {
	u, err := url.Parse("http://localhost:9000")
	if err != nil {
		return nil, err
	}

	u.Path += "exec"
	params := url.Values{}
	params.Add("query", query)
	u.RawQuery = params.Encode()
	queryURL := fmt.Sprintf("%v", u)

	res, err := http.Get(queryURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var logData LogData
	if err := json.Unmarshal(body, &logData); err != nil {
		return nil, err
	}

	return logData.Dataset, nil
}

func GetDashboardData() (models.DashboardData, error) {
	// Calculate the time 24 hours before the current time
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")

	queries := map[string]string{
		"TrafficOverTime":         fmt.Sprintf("SELECT timestamp AS minute, COUNT(*) AS count FROM logs WHERE timestamp > '%s' SAMPLE BY 1m", twentyFourHoursAgo),
		"TopClientIPs":            "SELECT client_ip, COUNT(*) AS count FROM logs GROUP BY client_ip ORDER BY count DESC LIMIT 6",
		"TopPaths":                "SELECT path, COUNT(*) AS count FROM logs GROUP BY path ORDER BY count DESC LIMIT 4",
		"AcceptHeaders":           "SELECT accept, COUNT(*) AS count FROM logs GROUP BY accept",
		"TopUserAgents":           "SELECT user_agent, COUNT(*) AS count FROM logs GROUP BY user_agent ORDER BY count DESC LIMIT 10",
		"TopRulesTriggered":       "SELECT ruleID, COUNT(*) AS count FROM logs WHERE ruleID != '0' GROUP BY ruleID ORDER BY count DESC LIMIT 10",
		"HighestBlockedIP":        "SELECT client_ip, COUNT(*) AS count FROM logs WHERE accept = false GROUP BY client_ip ORDER BY count DESC LIMIT 1",
	}

	data := models.DashboardData{}

	for key, query := range queries {
		results, err := executeQuery(query)
		if err != nil {
			return data, err
		}

		dataPoints := make([]models.DataPoint, len(results))
		for i, result := range results {
			label, ok := result[0].(string)
			if !ok {
				label = fmt.Sprintf("%v", result[0])
			}
			value, ok := result[1].(float64)
			if !ok {
				return data, fmt.Errorf("expected float64 but got %T", result[1])
			}
			dataPoints[i] = models.DataPoint{
				Label: label,
				Value: int(value),
			}
		}

		switch key {
		case "TrafficOverTime":
			data.TrafficOverTime = dataPoints
		case "TopClientIPs":
			data.TopClientIPs = dataPoints
		case "TopPaths":
			data.TopPaths = dataPoints
		case "AcceptHeaders":
			data.AcceptHeaders = dataPoints
		case "TopUserAgents":
			data.TopUserAgents = dataPoints
		case "TopRulesTriggered":
			data.TopRulesTriggered = dataPoints
		case "HighestBlockedIP":
			if len(dataPoints) > 0 {
				data.HighestBlockedIP = dataPoints[0]
			}
		}
	}

	return data, nil
}


func UpdateIncidentResponse(logID string, incidentResponseID string) error {
	u, err := url.Parse("http://localhost:9000")
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Construct the update query
	query := fmt.Sprintf(
		"UPDATE logs SET incidentResponseID = '%s' WHERE logID = '%s'",
		incidentResponseID, logID,
	)
	fmt.Print(incidentResponseID)
	fmt.Print(logID)

	u.Path += "exec"
	params := url.Values{}
	params.Add("query", query)
	u.RawQuery = params.Encode()
	url := fmt.Sprintf("%v", u)

	// Execute the query
	res, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to execute update query: %w", err)
	}
	defer res.Body.Close()

	// Read the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for errors in the response
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("update query failed: %s", string(body))
	}

	return nil
}
