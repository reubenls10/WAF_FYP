package models

type Log struct {
	Query     string          `json:"query" mapstructure:"query" struct:"query" `
	Columns   []QuestDBColumn `json:"columns" mapstructure:"columns" struct:"columns" `
	Timestamp int             `json:"timestamp" mapstructure:"timestamp" struct:"timestamp" `
	Dataset   [][]any         `json:"dataset" mapstructure:"dataset" struct:"dataset" `
	Count     int             `json:"count" mapstructure:"count" struct:"count" `
}

type QuestDBColumn struct {
	Name string `json:"name" mapstructure:"name" struct:"name" `
	Type string `json:"type" mapstructure:"type" struct:"type" `
}

type DataPoint struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

type DashboardData struct {
	TrafficOverTime   []DataPoint `json:"trafficOverTime"`
	TopClientIPs      []DataPoint `json:"topClientIPs"`
	TopPaths          []DataPoint `json:"topPaths"`
	AcceptHeaders     []DataPoint `json:"acceptHeaders"`
	TopUserAgents     []DataPoint `json:"topUserAgents"`
	TopRulesTriggered []DataPoint `json:"topRulesTriggered"`
	HighestBlockedIP  DataPoint   `json:"highestBlockedIP"`
}

type IncidentResponse struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	LogID             string `json:"logID"`
	ActionsTaken      string `json:"actionsTaken"`
	DateOfAction      string `json:"dateOfAction"`
	CreatedBy         string `json:"created_by"`
	Severity          string `json:"severity"`
	Status            string `json:"status"`
	ResolvedAt        string `json:"resolved_at"`
	CreatedByUsername string `json:"created_by_username"`
}

type Rule struct {
	FileName string
	RuleID   string
	Phase    string
	Action   string
	Msg      string
	RawRule  string
	On       bool
}

type CustomRule struct {
	RuleID    string `json:"rule_id"`
	Rule      string `json:"raw_rule"`
	IsEnabled bool   `json:"isEnabled"`
}

type ToggleRuleGroup struct {
	FileName string `json:"fileName"`
	Status   string `json:"status"`
}

type ToggleRule struct {
	RuleID    string `json:"ruleID"`
	IsEnabled bool   `json:"isEnabled"`
	FileName  string `json:"fileName"`
}