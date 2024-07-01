package storage

import (
	"bufio"
	"database/sql"
	"fmt"
	"fyp/models"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func CreateTables() {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create User Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			role TEXT NOT NULL,
			full_name TEXT,
			email TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`)
	if err != nil {
		panic(err)
	}

	// Create Incident Response Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS incident_responses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			log_id TEXT,
			title TEXT,
			actions_taken TEXT,
			date_of_action TEXT,
			created_by INTEGER,
			severity TEXT,
			status TEXT,
			resolved_at TIMESTAMP
		);`)
	if err != nil {
		panic(err)
	}

	// Create Settings Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`)
	if err != nil {
		panic(err)
	}

	// Create No Log Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS no_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL
		);`)
	if err != nil {
		panic(err)
	}

	// Create Reverse Proxies Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS reverse_proxies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			address TEXT NOT NULL
		);`)
	if err != nil {
		panic(err)
	}

	// Insert default data into Settings Table
	defaultSettings := map[string]string{
		"website_name":        "mywebsite.com",
		"port":                "8080",
		"website_description": "This is my website. The Web Application Firewall (WAF) implemented here is designed to protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet. It provides robust security features to safeguard against various online threats, ensuring the integrity and confidentiality of the data. This website serves as a comprehensive platform to demonstrate the capabilities of our WAF solution, which includes real-time threat monitoring, customizable rule sets, incident response, and a detailed analytics dashboard. It aims to offer a user-friendly interface for administrators to manage web security efficiently.",
		"waf_on":              "true",
	}

	for key, value := range defaultSettings {
		_, err = db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, key, value)
		if err != nil {
			panic(err)
		}
	}
}

// GetPortNumber retrieves the port number from the settings table in the SQLite database.
func GetPortNumber() (string, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return "", err
	}
	defer db.Close()

	var port string
	err = db.QueryRow("SELECT value FROM settings WHERE key = 'port'").Scan(&port)
	if err != nil {
		return "", err
	}

	return port, nil
}

// GetAllSettings retrieves all the settings data from the database.
func GetAllSettings() (models.Settings, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return models.Settings{}, err
	}
	defer db.Close()

	settings := models.Settings{}

	// Retrieve basic settings
	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return models.Settings{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return models.Settings{}, err
		}
		switch key {
		case "website_name":
			settings.WebsiteName = value
		case "port":
			settings.Port = value
		case "website_description":
			settings.WebsiteDescription = value
		case "waf_on":
			settings.WafOn = value == "true"
		}
	}

	// Retrieve no log paths
	noLogRows, err := db.Query(`SELECT path FROM no_log`)
	if err != nil {
		return models.Settings{}, err
	}
	defer noLogRows.Close()

	for noLogRows.Next() {
		var path string
		if err := noLogRows.Scan(&path); err != nil {
			return models.Settings{}, err
		}
		settings.NoLogPaths = append(settings.NoLogPaths, path)
	}

	// Retrieve reverse proxies
	proxyRows, err := db.Query(`SELECT address FROM reverse_proxies`)
	if err != nil {
		return models.Settings{}, err
	}
	defer proxyRows.Close()

	for proxyRows.Next() {
		var address string
		if err := proxyRows.Scan(&address); err != nil {
			return models.Settings{}, err
		}
		settings.ReverseProxies = append(settings.ReverseProxies, address)
	}

	return settings, nil
}

func GetWafStatus() bool {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		fmt.Printf("failed to open database: %v\n", err)
		return false
	}
	defer db.Close()

	var wafOn string
	err = db.QueryRow("SELECT value FROM settings WHERE key = 'waf_on'").Scan(&wafOn)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("WAF status not found\n")
			return false
		}
		fmt.Printf("failed to get WAF status: %v\n", err)
		return false
	}

	return wafOn == "true"
}

func GetNoLogs() ([]string) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		fmt.Printf("failed to open database: %v", err)
		return nil
		}
	defer db.Close()

	rows, err := db.Query("SELECT path FROM no_log")
	if err != nil {
		fmt.Printf("failed to query no_log paths: %v", err)
		return nil
		}
	defer rows.Close()

	var noLogPaths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			fmt.Printf("failed to scan row: %v", err)
			return nil
			}
		noLogPaths = append(noLogPaths, path)
	}

	if err = rows.Err(); err != nil {
		fmt.Printf("row iteration error: %v", err)
		return nil
	}

	return noLogPaths
}

func GetReverseProxyServers() ([]string ){
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		fmt.Printf("failed to open database: %v", err)
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT url FROM reverse_proxies")
	if err != nil {
		fmt.Printf("failed to query reverse_proxies: %v", err)
		return nil
	}
	defer rows.Close()

	var reverseProxyServers []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			fmt.Printf("failed to scan row: %v", err)
			return nil
		}
		reverseProxyServers = append(reverseProxyServers, url)
	}

	if err = rows.Err(); err != nil {
		fmt.Printf("row iteration error: %v", err)
		return nil
	}

	return reverseProxyServers
}

func EditSettings(settings models.Settings) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return false, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	updateQuery := `INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`

	// Update settings in the database
	_, err = db.Exec(updateQuery, "website_name", settings.WebsiteName)
	if err != nil {
		return false, fmt.Errorf("failed to update website_name: %v", err)
	}

	_, err = db.Exec(updateQuery, "port", settings.Port)
	if err != nil {
		return false, fmt.Errorf("failed to update port: %v", err)
	}

	_, err = db.Exec(updateQuery, "website_description", settings.WebsiteDescription)
	if err != nil {
		return false, fmt.Errorf("failed to update website_description: %v", err)
	}

	_, err = db.Exec(updateQuery, "waf_on", fmt.Sprintf("%t", settings.WafOn))
	if err != nil {
		return false, fmt.Errorf("failed to update waf_on: %v", err)
	}

	// Clear existing no_log paths
	_, err = db.Exec(`DELETE FROM no_log`)
	if err != nil {
		return false, fmt.Errorf("failed to clear no_log paths: %v", err)
	}

	// Clear existing reverse_proxies
	_, err = db.Exec(`DELETE FROM reverse_proxies`)
	if err != nil {
		return false, fmt.Errorf("failed to clear reverse_proxies: %v", err)
	}

	// Insert new no_log paths
	for _, path := range settings.NoLogPaths {
		_, err = db.Exec(`INSERT INTO no_log (path) VALUES (?)`, path)
		if err != nil {
			return false, fmt.Errorf("failed to insert no_log path: %v", err)
		}
	}

	// Insert new reverse_proxies
	for _, proxy := range settings.ReverseProxies {
		_, err = db.Exec(`INSERT INTO reverse_proxies (url) VALUES (?)`, proxy)
		if err != nil {
			return false, fmt.Errorf("failed to insert reverse_proxy: %v", err)
		}
	}

	return true, nil
}

func CreateRulesTable() (bool) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Check if the table already exists
	tableExists, err := doesTableExist(db, "rules")
	if err != nil {
		log.Fatalf("Failed to check if table exists: %v", err)
	}

	if tableExists {
		log.Println("Table 'rules' already exists.")
		return false
	}

	query := `
	CREATE TABLE rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_name TEXT,
		rule_iD TEXT,
		phase TEXT,
		action TEXT,
		msg TEXT,
		raw_rule TEXT,
		isEnabled BOOLEAN DEFAULT TRUE
	);`

	_, err = db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create rules table: %v", err)
	}

	return true
}

func doesTableExist(db *sql.DB, tableName string) (bool, error) {
	query := `
	SELECT name
	FROM sqlite_master
	WHERE type='table' AND name=?;`

	var name string
	err := db.QueryRow(query, tableName).Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	return name == tableName, nil
}

func LoadRules() (bool, error){
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	if CreateRulesTable(){
		fmt.Println("Loading Rules...")
		rulesFolder := "./coreruleset/rules"

		err = filepath.Walk(rulesFolder, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
				err = loadRulesFromFile(path, db)
				if err != nil {
					return fmt.Errorf("failed to load rules from file: %w", err)
				}
			}
			return nil
		})

		if err != nil {
			log.Fatalf("Failed to load rules: %v", err)
			return false, err
		}

		fmt.Println("Rules loaded successfully.")
		return true, nil
	}else{
		fmt.Println("Rules Ready")
		return true, nil
	}
}

func parseRule(line string) *models.Rule {

	rule := &models.Rule{
		RawRule: line,
	}

	// Extract RuleID
	idRegex := regexp.MustCompile(`id:(\d+)`)
	idMatch := idRegex.FindStringSubmatch(line)
	if len(idMatch) > 1 {
		rule.RuleID = idMatch[1]
	}

	// Extract Phase
	phaseRegex := regexp.MustCompile(`phase:(\d+)`)
	phaseMatch := phaseRegex.FindStringSubmatch(line)
	if len(phaseMatch) > 1 {
		rule.Phase = phaseMatch[1]
	}

	// Extract Action
	actions := []string{"deny", "block", "pass"}
	for _, action := range actions {
		if strings.Contains(line, action) {
			rule.Action = action
			break
		}
	}

	// Extract Msg
	msgRegex := regexp.MustCompile(`msg:'([^']*)'`)
	msgMatch := msgRegex.FindStringSubmatch(line)
	if len(msgMatch) > 1 {
		rule.Msg = msgMatch[1]
	}

	return rule
}
// Load rules from a given file
func loadRulesFromFile(filePath string, db *sql.DB) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileName := filepath.Base(filePath)
	scanner := bufio.NewScanner(file)
	var rawRuleBuilder strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == ""{
			// Skip comment lines
			continue
		}
		if strings.HasPrefix(line, "SecRule"){
			// If a previous rule is still being built, insert it into the DB
			if rawRuleBuilder.Len() > 0 && !strings.HasSuffix(rawRuleBuilder.String(), "chain\""){
				rule := parseRule(rawRuleBuilder.String())
				if rule != nil {
					rule.FileName = fileName
					err = insertRuleIntoDB(rule, db)
					if err != nil {
						return fmt.Errorf("failed to insert rule into DB: %w", err)
					}
				}
				rawRuleBuilder.Reset()
			}
			rawRuleBuilder.WriteString(line)
			continue
		} else if rawRuleBuilder.Len() > 0 && strings.HasSuffix(line, "\\") || strings.HasSuffix(line, "chain\""){
			rawRuleBuilder.WriteString(" " + strings.TrimSuffix(line, "\\"))
		} else {
			if rawRuleBuilder.Len() > 0 {
				rawRuleBuilder.WriteString(" " + line)
				// End of a multi-line rule
				rule := parseRule(rawRuleBuilder.String())
				if rule != nil {
					rule.FileName = fileName
					err = insertRuleIntoDB(rule, db)
					if err != nil {
						return fmt.Errorf("failed to insert rule into DB: %w", err)
					}
				}

				rawRuleBuilder.Reset()
			}
		}
	}

	// Insert the last rule if still being built
	if rawRuleBuilder.Len() > 0 {
		rule := parseRule(rawRuleBuilder.String())
		if rule != nil {
			rule.FileName = fileName
			err = insertRuleIntoDB(rule, db)
			if err != nil {
				return fmt.Errorf("failed to insert rule into DB: %w", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	return nil
}

func insertRuleIntoDB(rule *models.Rule, db *sql.DB) error {
	query := `
	INSERT INTO rules (file_name, rule_id, phase, action, msg, raw_rule)
	VALUES (?, ?, ?, ?, ?, ?);`

	_, err := db.Exec(query, rule.FileName, rule.RuleID, rule.Phase, rule.Action, rule.Msg, rule.RawRule)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

func ToggleRuleGroupDB(file_name string, isEnable bool) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	query := `
	UPDATE rules
	SET isEnabled = ?
	WHERE file_name = ?`

	_, err = db.Exec(query, isEnable, file_name)
	if err != nil {
		log.Fatalf("Failed to update rules: %v", err)
		return false, err
	}

	return true, nil
}

func ToggleRule(ruleID string, isEnable bool) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	query := `
	UPDATE rules
	SET isEnabled = ?
	WHERE rule_iD = ?`

	_, err = db.Exec(query, isEnable, ruleID)
	if err != nil {
		log.Fatalf("Failed to update rules: %v", err)
		return false, err
	}

	return true, nil
}

func CreateUser(username string, password string, role string, fullName string, email string) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}


	query := `
	INSERT INTO users (username, password, role, full_name, email, created_at)
	VALUES (?, ?, ?, ?, ?, datetime('now'));`

	_, err = db.Exec(query, username, string(hashedPassword), role, fullName, email)
	if err != nil {
		panic(err)
	}
}

func EditUser(user models.UserEdit) error {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	var updateQuery string
	var args []interface{}

	if user.OldPassword == "" || user.NewPassword == "" {
		// If either old or new password is empty, skip password update
		updateQuery = `
		UPDATE users 
		SET username = ?, role = ?, full_name = ?, email = ? 
		WHERE id = ?`
		args = []interface{}{user.Username, user.Role, user.FullName, user.Email, user.ID}
	} else {
		// Retrieve the existing user's password hash
		var currentHashedPassword string
		query := `SELECT password FROM users WHERE id = ?`
		err = db.QueryRow(query, user.ID).Scan(&currentHashedPassword)
		if err != nil {
			return fmt.Errorf("failed to retrieve current password: %w", err)
		}

		// Compare the provided old password with the current hashed password
		err = bcrypt.CompareHashAndPassword([]byte(currentHashedPassword), []byte(user.OldPassword))
		if err != nil {
			return fmt.Errorf("old password is incorrect: %w", err)
		}

		// Hash the new password
		hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(user.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash new password: %w", err)
		}

		// Update the user's details in the database, including the password
		updateQuery = `
		UPDATE users 
		SET username = ?, password = ?, role = ?, full_name = ?, email = ? 
		WHERE id = ?`
		args = []interface{}{user.Username, string(hashedNewPassword), user.Role, user.FullName, user.Email, user.ID}
	}

	_, err = db.Exec(updateQuery, args...)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}



func DeleteUser(username string) (bool, error){
	db, err := sql.Open("sqlite", "./mydatabase.db")
	if err != nil {
		return false, err
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return false, err
	}

	return true, nil
}


func GetUsers() []models.User{
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, username, password, role, full_name, email, created_at FROM users")
	if err != nil {
		log.Fatalf("Failed to select users: %v", err)
	}
	defer rows.Close()

	var users []models.User

	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.FullName, &user.Email, &user.CreatedAt)
		if err != nil {
			log.Fatalf("Failed to scan row: %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		log.Fatalf("Error reading rows: %v", err)
	}
	
	return users
}

func Login(username, password string) (bool, string, string) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	var storedPassword, role, id string
	query := "SELECT password, role, id FROM users WHERE username = ?"
	err = db.QueryRow(query, username).Scan(&storedPassword, &role, &id)
	if err != nil {
		if err == sql.ErrNoRows {
			// No such user
			return false, "", ""
		}
		log.Fatalf("Failed to query user: %v", err)
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		// Invalid password
		return false, "", ""
	}

	// Valid password
	return true, role, id
}

func AddIncidentResponse(ir models.IncidentResponse) (int64, bool) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return 0, false
	}
	defer db.Close()

	query := `
	INSERT INTO incident_responses (log_id, title, actions_taken, date_of_action, severity, status, resolved_at, created_by)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	result, err := db.Exec(query, ir.LogID, ir.Title, ir.ActionsTaken, ir.DateOfAction, ir.Severity, ir.Status, ir.ResolvedAt, ir.CreatedBy)
	if err != nil {
		log.Fatalf("Failed to insert incident response: %v", err)
		return 0, false
	}

	// Get the ID of the newly inserted entry
	id, err := result.LastInsertId()
	if err != nil {
		log.Fatalf("Failed to retrieve last insert id: %v", err)
		return 0, false
	}

	return id, true
}

func EditIncidentResponse(ir models.IncidentResponse) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	query := `
	UPDATE incident_responses
	SET log_id = ?, title = ?, actions_taken = ?, date_of_action = ?, severity = ?, status = ?, resolved_at = ?, created_by = ?
	WHERE id = ?;`

	_, err = db.Exec(query, ir.LogID, ir.Title, ir.ActionsTaken, ir.DateOfAction, ir.Severity, ir.Status, ir.ResolvedAt, ir.CreatedBy, ir.ID)
	if err != nil {
		log.Fatalf("Failed to update incident response: %v", err)
		return false, err
	}

	return true, nil
}

func GetIncidentResponse(incidentResponseID any) (*models.IncidentResponse, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return nil, err
	}
	defer db.Close()

	query := `
	SELECT *
	FROM incident_responses 
	WHERE id = ?`

	var incidentResponse models.IncidentResponse

	err = db.QueryRow(query, incidentResponseID).Scan(
		&incidentResponse.ID,
		&incidentResponse.LogID,
		&incidentResponse.Title,
		&incidentResponse.ActionsTaken,
		&incidentResponse.DateOfAction,
		&incidentResponse.CreatedBy,
		&incidentResponse.Severity,
		&incidentResponse.Status,
		&incidentResponse.ResolvedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			// No such incident response
			return nil, nil
		}
		log.Fatalf("Failed to query incident response: %v", err)
		return nil, err
	}

	// Fetch the username of the user who created the incident response
	var createdByUsername string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", incidentResponse.CreatedBy).Scan(&createdByUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			// No such user
			createdByUsername = "Unknown"
		} else {
			log.Fatalf("Failed to query username: %v", err)
			return nil, err
		}
	}

	// Assign the username to the incident response (assuming you have a field for this)
	incidentResponse.CreatedByUsername = createdByUsername

	return &incidentResponse, nil
}




func GetRuleGroups() ([]map[string]string, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	query := `
	SELECT file_name, isEnabled
	FROM rules`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %v", err)
	}
	defer rows.Close()

	ruleGroups := make(map[string][]bool)
	for rows.Next() {
		var fileName string
		var isEnabled bool
		if err := rows.Scan(&fileName, &isEnabled); err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		ruleGroups[fileName] = append(ruleGroups[fileName], isEnabled)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading rows: %v", err)
	}

	var result []map[string]string
	for fileName, statuses := range ruleGroups {
		status := determineStatus(statuses)
		result = append(result, map[string]string{"file_name": fileName, "status": status})
	}

	return result, nil
}

func GetRules(ruleGroup string) ([]models.Rule, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	query := `
	SELECT file_name, rule_id, phase, action, msg, raw_rule, isEnabled
	FROM rules 
	WHERE file_name = ?`
	fmt.Println(ruleGroup)

	rows, err := db.Query(query, ruleGroup + ".conf")
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %v", err)
	}
	defer rows.Close()

	var rules []models.Rule
	for rows.Next() {
		var rule models.Rule
		err := rows.Scan(&rule.FileName, &rule.RuleID, &rule.Phase, &rule.Action, &rule.Msg, &rule.RawRule, &rule.On)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading rows: %v", err)
	}

	return rules, nil
}

func GetRuleInfo(ruleID string) ([]models.Rule, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	query := `
	SELECT file_name, rule_id, phase, action, msg, raw_rule, isEnabled
	FROM rules 
	WHERE rule_id = ?`

	rows, err := db.Query(query, ruleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %v", err)
	}
	defer rows.Close()

	var rules []models.Rule
	for rows.Next() {
		var rule models.Rule
		err := rows.Scan(&rule.FileName, &rule.RuleID, &rule.Phase, &rule.Action, &rule.Msg, &rule.RawRule, &rule.On)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading rows: %v", err)
	}

	return rules, nil
}

func AddRule(rule models.Rule) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	query := `
	INSERT INTO rules (file_name, rule_id, phase, action, msg, raw_rule, isEnabled)
	VALUES (?, ?, ?, ?, ?, ?, ?);`

	_, err = db.Exec(query, rule.FileName, rule.RuleID, rule.Phase, rule.Action, rule.Msg, rule.RawRule, rule.On)
	if err != nil {
		log.Fatalf("Failed to execute query: %v", err)
		return false, err
	}

	return true, nil
}

func AddCustomRule(raw_rule models.CustomRule) (bool, error) {
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return false, err
	}
	defer db.Close()

	rule := parseRule(raw_rule.Rule)

	query := `
	INSERT INTO rules (file_name, rule_id, phase, action, msg, raw_rule, isEnabled)
	VALUES (?, ?, ?, ?, ?, ?, ?);`

	_, err = db.Exec(query, "CUSTOM-RULES.conf", rule.RuleID, rule.Phase, rule.Action, rule.Msg, rule.RawRule, raw_rule.IsEnabled)
	if err != nil {
		log.Fatalf("Failed to execute query: %v", err)
		return false, err
	}

	return true, nil
}


func determineStatus(statuses []bool) string {
	allOn := true
	allOff := true

	for _, status := range statuses {
		if status {
			allOff = false
		} else {
			allOn = false
		}
	}

	if allOn {
		return "ON"
	}
	if allOff {
		return "OFF"
	}
	return "PARTIALLY ON"
}