package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	_ "unsafe"

	"x-ui/config"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/sub"
	"x-ui/web"
	"x-ui/web/global"
	"x-ui/web/service"

	"github.com/op/go-logging"
)

func runWebServer() {
	log.Printf("Starting %v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Notice:
		logger.InitLogger(logging.NOTICE)
	case config.Warn:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatalf("Unknown log level: %v", config.GetLogLevel())
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	var server *web.Server
	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Fatalf("Error starting web server: %v", err)
		return
	}

	var subServer *sub.Server
	subServer = sub.NewServer()
	global.SetSubServer(subServer)
	err = subServer.Start()
	if err != nil {
		log.Fatalf("Error starting sub server: %v", err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	// Trap shutdown signals
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP signal. Restarting servers...")

			err := server.Stop()
			if err != nil {
				logger.Debug("Error stopping web server:", err)
			}
			err = subServer.Stop()
			if err != nil {
				logger.Debug("Error stopping sub server:", err)
			}

			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Fatalf("Error restarting web server: %v", err)
				return
			}
			log.Println("Web server restarted successfully.")

			subServer = sub.NewServer()
			global.SetSubServer(subServer)
			err = subServer.Start()
			if err != nil {
				log.Fatalf("Error restarting sub server: %v", err)
				return
			}
			log.Println("Sub server restarted successfully.")

		default:
			server.Stop()
			subServer.Stop()
			log.Println("Shutting down servers.")
			return
		}
	}
}

func resetSetting() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Failed to initialize database:", err)
		return
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("Failed to reset settings:", err)
	} else {
		fmt.Println("Settings successfully reset.")
	}
}

func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port failed, error info:", err)
		}

		webBasePath, err := settingService.GetBasePath()
		if err != nil {
			fmt.Println("get webBasePath failed, error info:", err)
		}

		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed, error info:", err)
		}

		username := userModel.Username
		userpasswd := userModel.Password
		if username == "" || userpasswd == "" {
			fmt.Println("current username or password is empty")
		}

		fmt.Println("current panel settings as follows:")
		if certFile == "" || keyFile == "" {
			fmt.Println("Warning: Panel is not secure with SSL")
		} else {
			fmt.Println("Panel is secure with SSL")
		}
		fmt.Println("username:", username)
		fmt.Println("password:", userpasswd)
		fmt.Println("port:", port)
		fmt.Println("webBasePath:", webBasePath)
	}
}

func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotEnabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotEnabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotEnabled[%v] success", status)
		}
	}
}

func updateTgbotSetting(tgBotToken string, tgBotChatid string, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Printf("Error setting Telegram bot token: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot token.")
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Printf("Error setting Telegram bot runtime: %v\n", err)
			return
		}
		logger.Infof("Successfully updated Telegram bot runtime to [%s].", tgBotRuntime)
	}

	if tgBotChatid != "" {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Printf("Error setting Telegram bot chat ID: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot chat ID.")
	}
}

func updateSetting(port int, username string, password string, webBasePath string, listenIP string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Database initialization failed:", err)
		return
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("Failed to set port:", err)
		} else {
			fmt.Printf("Port set successfully: %v\n", port)
		}
	}

	if username != "" || password != "" {
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("Failed to update username and password:", err)
		} else {
			fmt.Println("Username and password updated successfully")
		}
	}

	if webBasePath != "" {
		err := settingService.SetBasePath(webBasePath)
		if err != nil {
			fmt.Println("Failed to set base URI path:", err)
		} else {
			fmt.Println("Base URI path set successfully")
		}
	}

	if listenIP != "" {
		err := settingService.SetListen(listenIP)
		if err != nil {
			fmt.Println("Failed to set listen IP:", err)
		} else {
			fmt.Printf("listen %v set successfully", listenIP)
		}
	}
}

func updateCert(publicKey string, privateKey string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	if (privateKey != "" && publicKey != "") || (privateKey == "" && publicKey == "") {
		settingService := service.SettingService{}
		err = settingService.SetCertFile(publicKey)
		if err != nil {
			fmt.Println("set certificate public key failed:", err)
		} else {
			fmt.Println("set certificate public key success")
		}

		err = settingService.SetKeyFile(privateKey)
		if err != nil {
			fmt.Println("set certificate private key failed:", err)
		} else {
			fmt.Println("set certificate private key success")
		}
	} else {
		fmt.Println("both public and private key should be entered.")
	}
}

func GetCertificate(getCert bool) {
	if getCert {
		settingService := service.SettingService{}
		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		fmt.Println("cert:", certFile)
		fmt.Println("key:", keyFile)
	}
}

func GetListenIP(getListen bool) {
	if getListen {

		settingService := service.SettingService{}
		ListenIP, err := settingService.GetListen()
		if err != nil {
			log.Printf("Failed to retrieve listen IP: %v", err)
			return
		}

		fmt.Println("listenIP:", ListenIP)
	}
}

func migrateDb() {
	inboundService := service.InboundService{}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Start migrating database...")
	inboundService.MigrateDB()
	fmt.Println("Migration done!")
}

func removeSecret() {
	userService := service.UserService{}

	secretExists, err := userService.CheckSecretExistence()
	if err != nil {
		fmt.Println("Error checking secret existence:", err)
		return
	}

	if !secretExists {
		fmt.Println("No secret exists to remove.")
		return
	}

	err = userService.RemoveUserSecret()
	if err != nil {
		fmt.Println("Error removing secret:", err)
		return
	}

	settingService := service.SettingService{}
	err = settingService.SetSecretStatus(false)
	if err != nil {
		fmt.Println("Error updating secret status:", err)
		return
	}

	fmt.Println("Secret removed successfully.")
}

func parseTrojanURL(trojanURL string) (*model.Inbound, error) {
	// 例: trojan://password@domain:port?type=tcp&security=tls&fp=chrome&alpn=h3%2Ch2%2Chttp%2F1.1#Remark
	re := regexp.MustCompile(`^trojan://([^@]+)@([^:/?#]+):(\d+)\?([^#]*)#?(.*)$`)
	matches := re.FindStringSubmatch(trojanURL)
	if len(matches) < 6 {
		return nil, fmt.Errorf("无效的 Trojan URL 格式")
	}
	password := matches[1]
	domain := matches[2]
	port := matches[3]
	rawQuery := matches[4]
	remark := matches[5]
	if remark == "" {
		remark = "Trojan"
	}
	// 解析 query
	values, _ := url.ParseQuery(rawQuery)
	// 组装 Settings
	email := fmt.Sprintf("%s@%s", password[:6], domain)
	settings := map[string]interface{}{
		"clients": []map[string]interface{}{
			{
				"password": password,
				"email":    email,
				"enable":   true,
			},
		},
	}
	settingsBytes, _ := json.Marshal(settings)
	// 组装 StreamSettings
	network := values.Get("type")
	if network == "" {
		network = "tcp"
	}
	security := values.Get("security")
	if security == "" {
		security = "tls"
	}
	alpnStr := values.Get("alpn")
	alpn := []string{"h3", "h2", "http/1.1"}
	if alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}
	fingerprint := values.Get("fp")
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	cerfile := values.Get("cerfile")
	keyfile := values.Get("keyfile")
	streamSettings := map[string]interface{}{
		"network":  network,
		"security": security,
		"tlsSettings": map[string]interface{}{
			"alpn":        alpn,
			"fingerprint": fingerprint,
		},
	}
	// 支持cerfile和keyfile参数
	if cerfile != "" && keyfile != "" {
		streamSettings["tlsSettings"].(map[string]interface{})["certificates"] = []map[string]interface{}{
			{
				"certificateFile": cerfile,
				"keyFile":         keyfile,
			},
		}
	}
	streamSettingsBytes, _ := json.Marshal(streamSettings)
	// 转换端口
	portInt := 443
	fmt.Sscanf(port, "%d", &portInt)
	// Listen 默认值,侦听所有端口
	listen := ""
	//domain
	//if listen == "" {
	//	listen = "0.0.0.0"
	//}
	return &model.Inbound{
		Listen:         listen,
		Port:           portInt,
		Protocol:       "trojan",
		Settings:       string(settingsBytes),
		StreamSettings: string(streamSettingsBytes),
		Tag:            remark,
		Enable:         true,
		Remark:         remark,
	}, nil
}

func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var webBasePath string
	var listenIP string
	var getListen bool
	var webCertFile string
	var webKeyFile string
	var tgbottoken string
	var tgbotchatid string
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	var getCert bool
	var remove_secret bool
	var AddInboundJson string
	settingCmd.BoolVar(&reset, "reset", false, "Reset all settings")
	settingCmd.BoolVar(&show, "show", false, "Display current settings")
	settingCmd.BoolVar(&remove_secret, "remove_secret", false, "Remove secret key")
	settingCmd.IntVar(&port, "port", 0, "Set panel port number")
	settingCmd.StringVar(&username, "username", "", "Set login username")
	settingCmd.StringVar(&password, "password", "", "Set login password")
	settingCmd.StringVar(&webBasePath, "webBasePath", "", "Set base path for Panel")
	settingCmd.StringVar(&listenIP, "listenIP", "", "set panel listenIP IP")
	settingCmd.BoolVar(&getListen, "getListen", false, "Display current panel listenIP IP")
	settingCmd.BoolVar(&getCert, "getCert", false, "Display current certificate settings")
	settingCmd.StringVar(&webCertFile, "webCert", "", "Set path to public key file for panel")
	settingCmd.StringVar(&webKeyFile, "webCertKey", "", "Set path to private key file for panel")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "Set token for Telegram bot")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "Set cron time for Telegram bot notifications")
	settingCmd.StringVar(&tgbotchatid, "tgbotchatid", "", "Set chat ID for Telegram bot notifications")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "Enable notifications via Telegram bot")
	settingCmd.StringVar(&AddInboundJson, "AddInbound", "", "Add inbound by JSON string")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    migrate        migrate form other/old x-ui")
		fmt.Println("    setting        set settings")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "migrate":
		migrateDb()
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		// 修正：初始化数据库和服务对象
		if AddInboundJson == "" && len(os.Args) > 2 && os.Args[2] == "-AddInbound" {
			fmt.Println("未检测到参数，自动添加默认 Trojan 入站")
			err := database.InitDB(config.GetDBPath())
			if err != nil {
				fmt.Println("数据库初始化失败:", err)
				return
			}
			inboundService := service.InboundService{}
			// 获取系统第一个用户ID
			userService := service.UserService{}
			userModel, _ := userService.GetFirstUser()
			userId := userModel.Id
			// 支持从环境变量或命令行参数传入 domain/password/email
			domain := os.Getenv("TROJAN_DOMAIN")
			if domain == "" {
				domain = "example.com" // 推荐用实际域名，避免0.0.0.0
			}
			password := os.Getenv("TROJAN_PASSWORD")
			if password == "" {
				// 随机生成16位密码
				const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
				b := make([]byte, 16)
				for i := range b {
					b[i] = letters[int(uint32(os.Getpid())+uint32(os.Getppid())+uint32(os.Getuid())+uint32(os.Getgid())+uint32(os.Geteuid())+uint32(os.Getegid())+uint32(os.Getppid())+uint32(i))%len(letters)]
				}
				password = string(b)
			}
			// 随机端口，范围10000-60000
			port := 10000 + (int(uint32(os.Getpid())+uint32(os.Getppid())+uint32(os.Getuid())+uint32(os.Getgid())+uint32(os.Geteuid())+uint32(os.Getegid())+uint32(os.Getppid())) % 50000)
			remark := "DefaultTrojan"
			email := fmt.Sprintf("%s@%s", password[:6], domain)
			settings := map[string]interface{}{
				"clients": []map[string]interface{}{
					{
						"password": password,
						"email":    email,
						"enable":   true,
					},
				},
			}
			settingsBytes, _ := json.Marshal(settings)
			streamSettings := map[string]interface{}{
				"network":  "tcp",
				"security": "tls",
				"tlsSettings": map[string]interface{}{
					"alpn":        []string{"h3", "h2", "http/1.1"},
					"fingerprint": "chrome",
				},
			}
			streamSettingsBytes, _ := json.Marshal(streamSettings)
			inbound := &model.Inbound{
				Listen:         "0.0.0.0",
				Port:           port,
				Protocol:       "trojan",
				Settings:       string(settingsBytes),
				StreamSettings: string(streamSettingsBytes),
				Tag:            remark,
				Enable:         true,
				Remark:         remark,
				UserId:         userId, // 关键：写入用户ID
			}
			result, needRestart, err := inboundService.AddInbound(inbound)
			if err != nil {
				fmt.Println("添加默认 Trojan 入站失败:", err)
			} else {
				fmt.Printf("添加默认 Trojan 入站成功，ID: %d, 端口: %d, 是否需要重启: %v\n", result.Id, result.Port, needRestart)
			}
			// 新增：打印所有已保存的 inbounds（详细信息，便于排查）
			allInbounds, err := inboundService.GetAllInbounds()
			if err == nil {
				fmt.Println("当前数据库已保存的所有入站（详细）：")
				for _, ib := range allInbounds {
					fmt.Printf("ID: %d, 协议: %s, 端口: %d, 备注: %s, 启用: %v, Listen: %s, Tag: %s, Settings: %s\n", ib.Id, ib.Protocol, ib.Port, ib.Remark, ib.Enable, ib.Listen, ib.Tag, ib.Settings)
				}
			} else {
				fmt.Println("读取数据库入站失败：", err)
			}
			return
		}
		// 新增处理 AddInbound 参数
		if AddInboundJson != "" {
			fmt.Println("收到的 AddInbound 参数如下：")
			fmt.Println(AddInboundJson)
			err := database.InitDB(config.GetDBPath())
			if err != nil {
				fmt.Println("数据库初始化失败:", err)
				return
			}
			var inbound *model.Inbound
			if strings.HasPrefix(AddInboundJson, "trojan://") {
				fmt.Println("解析 Trojan 开头字符串")
				inbound, err = parseTrojanURL(AddInboundJson)
				if err != nil {
					fmt.Println("解析 Trojan URL 失败:", err)
					return
				}
			} else {
				var inboundObj model.Inbound
				fmt.Println("解析 Trojan JSON字符串")
				if err := json.Unmarshal([]byte(AddInboundJson), &inboundObj); err != nil {
					fmt.Println("解析入站 JSON 失败:", err)
					return
				}
				// 设置默认值（参考控制器逻辑）
				if inboundObj.Listen == "" {
					inboundObj.Listen = "0.0.0.0"
				}
				if inboundObj.Protocol == "" {
					inboundObj.Protocol = "trojan"
				}
				// Tag 规则与控制器保持一致
				if inboundObj.Listen == "" || inboundObj.Listen == "0.0.0.0" || inboundObj.Listen == "::" || inboundObj.Listen == "::0" {
					inboundObj.Tag = fmt.Sprintf("inbound-%v", inboundObj.Port)
				} else {
					inboundObj.Tag = fmt.Sprintf("inbound-%v:%v", inboundObj.Listen, inboundObj.Port)
				}
				inbound = &inboundObj
			}
			// 获取系统第一个用户ID
			userService := service.UserService{}
			userModel, _ := userService.GetFirstUser()
			inbound.UserId = userModel.Id
			inboundService := service.InboundService{}
			result, needRestart, err := inboundService.AddInbound(inbound)
			if err != nil {
				fmt.Println("带参数添加入站失败:", err)
			} else {
				fmt.Printf("带参数添加入站成功，ID: %d, 是否需要重启: %v\n", result.Id, needRestart)
				fmt.Println("请刷新页面查看新入站，若未显示可尝试重启 x-ui 服务。")
			}
			// 新增：打印所有已保存的 inbounds（详细信息，便于排查）
			allInbounds, err := inboundService.GetAllInbounds()
			if err == nil {
				fmt.Println("当前数据库已保存的所有入站（详细）：")
				for _, ib := range allInbounds {
					fmt.Printf("ID: %d, 协议: %s, 端口: %d, 备注: %s, 启用: %v, Listen: %s, Tag: %s, Settings: %s\n", ib.Id, ib.Protocol, ib.Port, ib.Remark, ib.Enable, ib.Listen, ib.Tag, ib.Settings)
				}
			} else {
				fmt.Println("读取数据库入站失败：", err)
			}
			return
		}
		if reset {
			resetSetting()
		} else {
			updateSetting(port, username, password, webBasePath, listenIP)
		}
		if show {
			showSetting(show)
		}
		if getListen {
			GetListenIP(getListen)
		}
		if getCert {
			GetCertificate(getCert)
		}
		if (tgbottoken != "") || (tgbotchatid != "") || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
		if remove_secret {
			removeSecret()
		}
		if enabletgbot {
			updateTgbotEnableSts(enabletgbot)
		}
	case "cert":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			updateCert("", "")
		} else {
			updateCert(webCertFile, webKeyFile)
		}
	default:
		fmt.Println("Invalid subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
