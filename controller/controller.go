package controller

import (
	"fmt"
	"fyp/conf"
	"fyp/models"
	"fyp/storage"
	"strconv"
)

func LoadRules() (bool, error){
	storage.LoadRules()

	return true, nil
}

func GetDashboardData() (models.DashboardData, error) {
	
	dd, err := storage.GetDashboardData()
	if err != nil {
		fmt.Println(err)
	}

	return dd, nil
}

func GetLogs() (*models.Log, error){
	logData,_ := storage.GetLogs()

	return logData, nil
}

func GetRuleGroups() ([]map[string]string, error){
	rulesData,_ := storage.GetRuleGroups()

	return rulesData, nil
}

func GetRules(ruleGroup string) ([]models.Rule){
	rulesData,_ := storage.GetRules(ruleGroup)

	return rulesData
}

func GetRuleInfo(ruleID string) ([]models.Rule){
	rulesData,_ := storage.GetRuleInfo(ruleID)
	fmt.Println("2")
	return rulesData
}

func AddRule(rule models.Rule) (bool, error){
	return storage.AddRule(rule)
}

func AddCustomRule(rule models.CustomRule) (bool, error){
	_, err := storage.AddCustomRule(rule)
	if err != nil{
		return false, err
	}

	err = conf.AddCustomRule(rule.Rule)

	if err != nil{
		return false, err
	}
	return true, nil
}

func ToggleRuleGroup(fileName string, status string)(bool, error){
	isEnable := true
	if status == "ON" || status == "PARTIALLY ON" {
		isEnable = false
	} 
	_, err := storage.ToggleRuleGroupDB(fileName, isEnable)
	if err != nil{
		return false, err
	}

	err = conf.ToggleRuleGroup(fileName, isEnable)

	if err != nil{
		return false, err
	}
	return true, nil
}

func ToggleRule(ruleID string, isEnable bool, fileName string)(bool, error){
	_, err := storage.ToggleRule(ruleID, isEnable)
	if err != nil{
		return false, err
	}
	err = conf.ToggleRule(fileName, ruleID, isEnable)
	if err != nil{
		return false, err
	}
	return true, nil
}


func GetLog(logID string) (*models.Log, *models.IncidentResponse, error){
	logData,_ := storage.GetLog(logID)
	fmt.Println("IR ID: ", logData.Dataset[0][5])
	incidentResponse, err := storage.GetIncidentResponse(logData.Dataset[0][5])
	if err != nil {
		fmt.Println(err)
	}

	return logData, incidentResponse, nil
}


func CreateUser(username string, password string, role string, fullName string, email string){
	storage.CreateUser(username, password ,role, fullName, email )
}

func EditUser(user models.UserEdit)(error){
	return storage.EditUser(user)
}

func DeleteUser(username string)(bool, error){
	return storage.DeleteUser(username )
}

func GetUsers() []models.User{
	return storage.GetUsers()
}

func Login(username string, password string) (bool,string, string){
	return storage.Login(username , password )
}

func AddIncidentResponse(incidentResponse models.IncidentResponse) bool{
	// Update SQLite
	incidentResponseID, ok := storage.AddIncidentResponse(incidentResponse)

	if ok{
		err := storage.UpdateIncidentResponse(incidentResponse.LogID, strconv.FormatInt(incidentResponseID, 10))
		if err != nil {
			fmt.Println(err)
		}
	}else{
		return false
	}

	return true
}


func EditIncidentResponse(incidentResponse models.IncidentResponse) bool{
	// Update SQLite
	ok, err := storage.EditIncidentResponse(incidentResponse)

	if err != nil {
		fmt.Println(err)
	}

	return ok
}

func GetPortNumber() (string, error){
	return storage.GetPortNumber()
}

func GetAllSettings() (models.Settings, error){
	return storage.GetAllSettings()
}

func EditSettings(settings models.Settings) (bool, error){
	return storage.EditSettings(settings)
}