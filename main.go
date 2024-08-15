package main

import (
	"context"
	"encoding/json"
	"fmt"
	"fyp/controller"
	"fyp/models"
	"fyp/storage"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/corazawaf/coraza/v3"
	"github.com/gin-gonic/gin"
	qdb "github.com/questdb/go-questdb-client/v2"
	_ "modernc.org/sqlite"
)

var ctx = context.TODO()
var sender, errQuestDB = qdb.NewLineSender(ctx)
var noLog = storage.GetNoLogs()
var wafOn = storage.GetWafStatus()

// TODO : Load reverseProxy Server
var reverse_proxies = storage.GetReverseProxyServers()




func main() {
	router := gin.Default()

	if errQuestDB != nil {
		fmt.Println(errQuestDB)
	}

	// SQLite Setup Tables
	storage.CreateTables()

	// Load Coraza Rules
	controller.LoadRules()

	// Make sure to close the sender on exit to release resources.
	defer sender.Close()

	// CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == "GET" {
			// c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, User-Agent, Key, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform")
		} else{
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, User-Agent, Key, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform")
		}
		
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	if wafOn{
		router.Use(CorazaMiddleware())
	} 

	router.GET("/api/admin/logs", func(c *gin.Context) {
		logs, err := controller.GetLogs()
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"logs": logs,
		})
	})

	router.POST("/api/admin/login", func(c *gin.Context) {
        var credentials struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        if err := c.BindJSON(&credentials); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
            return
        }

		ok, role, id := controller.Login(credentials.Username, credentials.Password)

        if ok {
            c.JSON(http.StatusOK, gin.H{
                "message": "Login successful",
				"role" : role,
				"id" : id,
            })
        } else {
            c.JSON(http.StatusOK, gin.H{
                "message": "Invalid username or password",
            })
        }
    })

	router.POST("/api/admin/user/create", func(c *gin.Context) {
 		var user models.User
        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
            return
        }

        controller.CreateUser(user.Username, user.Password, user.Role, user.FullName, user.Email)
		c.JSON(http.StatusOK, gin.H{
			"message": "User Added",
		})
	})

	
	router.POST("/api/sampleApp/item", func(c *gin.Context) {

		c.JSON(http.StatusOK, gin.H{
			"message": "OK!",
		})
    })

	router.GET("/api/sampleApp/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "OK!",
		})
    })

	router.POST("/api/admin/user/edit", func(c *gin.Context) {
 		var user models.UserEdit
        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
            return
        }

        controller.EditUser(user)
		c.JSON(http.StatusOK, gin.H{
			"message": "User Updated",
		})
	})

	router.GET("/api/admin/user/delete/:username", func(c *gin.Context) {
		username := c.Param("username")

        ok, err := controller.DeleteUser(username)

		if err != nil{
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Failed to Delete User",
			})
		}

		if ok{
			c.JSON(http.StatusOK, gin.H{
				"message": "User Deleted",
			})
		}
	})


	router.GET("/api/admin/users", func(c *gin.Context) {
		users := controller.GetUsers()
		c.JSON(http.StatusOK, gin.H{
			"users": users,
		})
	})

	router.GET("/api/admin/log/:logID", func(c *gin.Context) {
		// Extract the logID from the URL parameter
		logID := c.Param("logID")

		// Call your controller function to get the logs (or a specific log based on logID)
		log, incidentResponse, err := controller.GetLog(logID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to fetch log"})
			return
		}

		// Return the log as JSON
		c.JSON(http.StatusOK, gin.H{
			"log": log,
			"incidentResponse": incidentResponse, 
		})
	})

	router.POST("/api/admin/log/:logID/response", func(c *gin.Context) {
		var incidentResponse models.IncidentResponse
		if err := c.ShouldBindJSON(&incidentResponse); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok := controller.AddIncidentResponse(incidentResponse)
		if !ok{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save incident response"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Incident response saved"})
	})

	router.POST("/api/admin/response/update", func(c *gin.Context) {
		var incidentResponse models.IncidentResponse
		if err := c.ShouldBindJSON(&incidentResponse); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok := controller.EditIncidentResponse(incidentResponse)
		if !ok{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save incident response"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Incident response saved"})
	})

	router.GET("/api/admin/dashboard", func(c *gin.Context) {
		dashboard, err := controller.GetDashboardData()
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"dashboard": dashboard,
		})
	})

	router.GET("/api/admin/rules", func(c *gin.Context) {
		ruleGroups, err := controller.GetRuleGroups()
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"ruleGroups": ruleGroups,
		})
	})


	router.POST("api/admin/rules/add", func(c *gin.Context) {
		var rule models.CustomRule
		if err := c.ShouldBindJSON(&rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok, err := controller.AddCustomRule(rule)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusConflict, gin.H{
				"error": err.Error(),
			})
		} else{
			c.JSON(http.StatusOK, gin.H{
				"success": ok,
			})
		}
	})

	router.GET("/api/admin/rules/:ruleGroup", func(c *gin.Context) {
		ruleGroup := c.Param("ruleGroup")

		rules := controller.GetRules(ruleGroup)
		c.JSON(http.StatusOK, gin.H{
			"rules": rules,
		})
	})

	router.GET("/api/admin/rule/:ruleID", func(c *gin.Context) {
		ruleID := c.Param("ruleID")
		fmt.Println(ruleID)

		rule := controller.GetRuleInfo(ruleID)
		fmt.Println(rule)
		c.JSON(http.StatusOK, gin.H{
			"rule": rule,
		})
	})

	router.POST("api/admin/rules/group/toggle", func(c *gin.Context) {
		var toggleRuleGroup models.ToggleRuleGroup
		if err := c.ShouldBindJSON(&toggleRuleGroup); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok, err := controller.ToggleRuleGroup(toggleRuleGroup.FileName, toggleRuleGroup.Status)
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"success": ok,
		})
	})

	router.POST("api/admin/rule/toggle", func(c *gin.Context) {
		var toggleRule models.ToggleRule
		if err := c.ShouldBindJSON(&toggleRule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok, err := controller.ToggleRule(toggleRule.RuleID, toggleRule.IsEnabled, toggleRule.FileName)
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"success": ok,
		})
	})

	router.GET("/api/admin/settings", func(c *gin.Context) {
		settings, err := controller.GetAllSettings()
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"settings": settings,
		})
	})

	router.POST("/api/admin/settings", func(c *gin.Context) {
		var settings models.Settings
		if err := c.ShouldBindJSON(&settings); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok, err := controller.EditSettings(settings)
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"success": ok,
		})
	})

	// router.Use(reverseProxy("http://localhost:5173"))
	for _, proxy := range reverse_proxies { 
		router.Use(reverseProxy("http://" + proxy))
    } 



	port_number, err := controller.GetPortNumber()
	if err != nil {
		fmt.Println(err)
	}

	router.Run("localhost:" + port_number)
}

func reverseProxy(target string) gin.HandlerFunc {
	return func(c *gin.Context) {
		url, _ := url.Parse(target)

		proxy := httputil.NewSingleHostReverseProxy(url)
		proxy.ModifyResponse = func(response *http.Response) error {
			response.Header.Set("X-Proxy", "Gin-Reverse-Proxy")
			return nil
		}

		proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
			c.JSON(http.StatusBadGateway, gin.H{"message": "Bad Gateway"})
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func CorazaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		port := 0
		var err error

		// Converting Port string to int
		if c.Request.URL.Port() == "" {
			port = 5173
		} else {
			port, err = strconv.Atoi(c.Request.URL.Port())
			if err != nil {
				fmt.Println(err)
			}
		}

		// Read the request body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			fmt.Println(err)
		}
		// Make a copy of the request body for WAF processing
		bodyCopy := make([]byte, len(body))
		copy(bodyCopy, body)
		// Restore the request body so that it can be read again by other handlers
		c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

		var headerContentType *string = nil
		originalString := c.Request.Header.Get("content-type")
		headerContentType = &originalString


		req := Request{
			RemoteAddr:        c.Request.RemoteAddr,
			Path:              c.Request.URL.String(),
			Port:              port,
			Query:             c.Request.URL.RawQuery,
			HTTPVersion:       c.Request.Proto,
			Method:            c.Request.Method,
			Headers:           c.Request.Header.Get("Access-Control-Allow-Origin"),
			Body:              string(bodyCopy),
			HeaderHost:        c.Request.Header.Get("host"),
			HeaderContentType: headerContentType,
		}
		fmt.Println(c.Request.RemoteAddr)

		status, ruleID := CorazaModule(req)
		if status != 200 {
			logRequest(c, false, ruleID)
			c.JSON(status, gin.H{"error": "Request blocked by WAF"})
			c.Abort()
			return
		}
		logRequest(c, true, ruleID)

		c.Next() // Continue to the next handler if not blocked
	}
}


type Request struct {
	RemoteAddr        string
	Path              string
	Port              int
	Query             string
	HTTPVersion       string
	Method            string
	Headers           string
	Body              string
	HeaderHost        string
	HeaderUserAgent   string
	HeaderContentType *string
}

func CorazaModule(req Request) (status int, ruleID int) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectivesFromFile("coraza.conf").
		WithDirectivesFromFile("coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("coreruleset/rules/*.conf"))

	if err != nil {
		log.Fatalf("Error creating WAF: %v", err)
		return 500, 0
	}

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		log.Println("Transaction closed successfully")
		tx.Close()
	}()
	fmt.Println(req.RemoteAddr)
	tx.ProcessConnection(req.RemoteAddr, req.Port, "172.29.122.57", 80)

	tx.ProcessURI(req.Path, req.Method, req.HTTPVersion)
	

	tx.SetServerName(req.HeaderHost)

	tx.AddRequestHeader("host", req.HeaderHost)
	tx.AddRequestHeader("user-agent", req.HeaderUserAgent)
	tx.AddRequestHeader("method", req.Method)

	if req.Method == "POST"{
		if req.HeaderContentType != nil {
			tx.AddRequestHeader("content-type", *req.HeaderContentType)
		}
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		log.Printf("Transaction was interrupted with status %d\n", it.Status)
		return it.Status, it.RuleID
	}

	if tx.IsRequestBodyAccessible() {
		if req.Body != "" {
			bodyReader := strings.NewReader(req.Body)
			it, _, err := tx.ReadRequestBodyFrom(bodyReader)
			if err != nil {
				log.Printf("Failed to append request body: %v", err)
				return 500, it.RuleID
			}

			if it != nil {
				log.Printf("Transaction was (1)interrupted with status %d\n", it.Status)
				return it.Status, it.RuleID
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				log.Printf("Failed to get the request body: %v", err)
				return 500, it.RuleID
			}

			var remainingBody strings.Builder
			_, err = io.Copy(&remainingBody, rbr)
			if err != nil {
				log.Printf("Failed to read the remaining request body: %v", err)
				return 500, it.RuleID
			}

			req.Body = remainingBody.String()
		}
	}

	if it, err := tx.ProcessRequestBody(); it != nil {
		if err != nil {
			log.Printf("Error Processing Request Body, %s", err)
			return 500, it.RuleID
		}
		log.Printf("Transaction was (2)interrupted with status %d\n", it.Status)
		return it.Status, it.RuleID
	}
	
	return 200, 0
}

func logRequest(c *gin.Context, ok bool, ruleID int) {
	if inNolog(c.Request.URL.String()) {
		fmt.Println("WONT LOG ", c.Request.URL.String())
		return
	}
	fmt.Println("LOGGING ", c.Request.URL.String())

	// Read the request body
	jsonData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		fmt.Println("ReadAll ERROR : ", err)
	}

	// Restore the request body so it can be read again
	c.Request.Body = io.NopCloser(strings.NewReader(string(jsonData)))

	// Convert request body to a string
	requestBody := string(jsonData)

	// Convert headers to a JSON string
	headersJSON, err := json.Marshal(c.Request.Header)
	if err != nil {
		fmt.Println("Failed to marshal headers: ", err)
		headersJSON = []byte("{}") // Default to empty JSON object if marshalling fails
	}

	id := uuid.New()
	userAgent := c.Request.UserAgent()
	referer := c.Request.Referer()
	serverIP := c.Request.Host

	err = sender.
		Table("logs").
		StringColumn("logID", id.String()).
		StringColumn("method", c.Request.Method).
		StringColumn("path", c.Request.URL.String()).
		StringColumn("protocol", c.Request.Proto).
		StringColumn("client_ip", c.Request.RemoteAddr).
		StringColumn("incidentResponseID", "").
		StringColumn("ruleID", strconv.Itoa(ruleID)).
		BoolColumn("accept", ok).
		StringColumn("user_agent", userAgent).
		StringColumn("referer", referer).
		StringColumn("request_body", requestBody).
		StringColumn("headers", string(headersJSON)).
		StringColumn("server_ip", serverIP).
		AtNow(ctx)

	if err != nil {
		fmt.Println("Sender ERROR : ", err)
	}

	err = sender.Flush(ctx)
	if err != nil {
		log.Fatal(err)
	}
}

func inNolog(path string)bool{
	for _, prefix := range noLog {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}