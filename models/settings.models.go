package models

type Settings struct {
	WebsiteName        string   `json:"WebsiteName"`
	Port               string   `json:"Port"`
	WebsiteDescription string   `json:"WebsiteDescription"`
	WafOn              bool     `json:"WafOn"`
	NoLogPaths         []string `json:"NoLogPaths"`
	ReverseProxies     []string `json:"ReverseProxies"`
}