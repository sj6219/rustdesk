lazy_static::lazy_static! {
pub static ref T: std::collections::HashMap<&'static str, &'static str> =
    [
        ("Status", "狀態"),
        ("Your Desktop", "您的桌面"),
        ("desk_tip", "您可以透過此 ID 及密碼存取您的桌面"),
        ("Password", "密碼"),
        ("Ready", "就緒"),
        ("Established", "已建立"),
        ("connecting_status", "正在連接至 RustDesk 網路..."),
        ("Enable Service", "啟用服務"),
        ("Start Service", "啟動服務"),
        ("Service is running", "服務正在運行"),
        ("Service is not running", "服務尚未執行"),
        ("not_ready_status", "尚未就緒。請檢查您的網路連線"),
        ("Control Remote Desktop", "控制遠端桌面"),
        ("Transfer File", "傳輸檔案"),
        ("Connect", "連接"),
        ("Recent Sessions", "近期的工作階段"),
        ("Address Book", "通訊錄"),
        ("Confirmation", "確認"),
        ("TCP Tunneling", "TCP 通道"),
        ("Remove", "移除"),
        ("Refresh random password", "重新產生隨機密碼"),
        ("Set your own password", "自行設置密碼"),
        ("Enable Keyboard/Mouse", "啟用鍵盤/滑鼠"),
        ("Enable Clipboard", "啟用剪貼簿"),
        ("Enable File Transfer", "啟用檔案傳輸"),
        ("Enable TCP Tunneling", "啟用 TCP 通道"),
        ("IP Whitelisting", "IP 白名單"),
        ("ID/Relay Server", "ID/轉送伺服器"),
        ("Import Server Config", "匯入伺服器設定"),
        ("Export Server Config", "導出服務器配置"),
        ("Import server configuration successfully", "匯入伺服器設定成功"),
        ("Export server configuration successfully", "導出服務器配置信息成功"),
        ("Invalid server configuration", "無效的伺服器設定"),
        ("Clipboard is empty", "剪貼簿是空的"),
        ("Stop service", "停止服務"),
        ("Change ID", "更改 ID"),
        ("Website", "網站"),
        ("About", "關於"),
        ("Slogan_tip", ""),
        ("Privacy Statement", ""),
        ("Mute", "靜音"),
        ("Audio Input", "音訊輸入"),
        ("Enhancements", "增強功能"),
        ("Hardware Codec", "硬件編解碼"),
        ("Adaptive Bitrate", "自適應碼率"),
        ("ID Server", "ID 伺服器"),
        ("Relay Server", "轉送伺服器"),
        ("API Server", "API 伺服器"),
        ("invalid_http", "開頭必須為 http:// 或 https://"),
        ("Invalid IP", "IP 無效"),
        ("id_change_tip", "僅能使用以下字元：a-z、A-Z、0-9、_ (底線)。首字元必須為 a-z 或 A-Z。長度介於 6 到 16 之間。"),
        ("Invalid format", "格式無效"),
        ("server_not_support", "服務器暫不支持"),
        ("Not available", "無法使用"),
        ("Too frequent", "修改過於頻繁，請稍後再試。"),
        ("Cancel", "取消"),
        ("Skip", "跳過"),
        ("Close", "關閉"),
        ("Retry", "重試"),
        ("OK", "確定"),
        ("Password Required", "需要密碼"),
        ("Please enter your password", "請輸入您的密碼"),
        ("Remember password", "記住密碼"),
        ("Wrong Password", "密碼錯誤"),
        ("Do you want to enter again?", "您要重新輸入嗎？"),
        ("Connection Error", "連線錯誤"),
        ("Error", "錯誤"),
        ("Reset by the peer", "對方重置了連線"),
        ("Connecting...", "正在連接..."),
        ("Connection in progress. Please wait.", "正在連接，請稍候。"),
        ("Please try 1 minute later", "請於 1 分鐘後再試"),
        ("Login Error", "登入錯誤"),
        ("Successful", "成功"),
        ("Connected, waiting for image...", "已連線，等待畫面傳輸..."),
        ("Name", "名稱"),
        ("Type", "類型"),
        ("Modified", "修改時間"),
        ("Size", "大小"),
        ("Show Hidden Files", "顯示隱藏檔案"),
        ("Receive", "接收"),
        ("Send", "傳送"),
        ("Refresh File", "刷新文件"),
        ("Local", "本地"),
        ("Remote", "遠端"),
        ("Remote Computer", "遠端電腦"),
        ("Local Computer", "本地電腦"),
        ("Confirm Delete", "確認刪除"),
        ("Delete", "刪除"),
        ("Properties", "屬性"),
        ("Multi Select", "多選"),
        ("Select All", "全選"),
        ("Unselect All", "取消全選"),
        ("Empty Directory", "空文件夾"),
        ("Not an empty directory", "不是一個空文件夾"),
        ("Are you sure you want to delete this file?", "您確定要刪除此檔案嗎？"),
        ("Are you sure you want to delete this empty directory?", "您確定要刪除此空目錄嗎？"),
        ("Are you sure you want to delete the file of this directory?", "您確定要刪除此目錄中的檔案嗎？"),
        ("Do this for all conflicts", "套用到其他衝突"),
        ("This is irreversible!", "此操作不可逆！"),
        ("Deleting", "正在刪除"),
        ("files", "檔案"),
        ("Waiting", "正在等候..."),
        ("Finished", "已完成"),
        ("Speed", "速度"),
        ("Custom Image Quality", "自訂圖片品質"),
        ("Privacy mode", "隱私模式"),
        ("Block user input", "封鎖使用者輸入"),
        ("Unblock user input", "取消封鎖使用者輸入"),
        ("Adjust Window", "調整視窗"),
        ("Original", "原始"),
        ("Shrink", "縮減"),
        ("Stretch", "延展"),
        ("Scrollbar", "滾動條"),
        ("ScrollAuto", "自動滾動"),
        ("Good image quality", "畫面品質良好"),
        ("Balanced", "平衡"),
        ("Optimize reaction time", "回應速度最佳化"),
        ("Custom", "自定義"),
        ("Show remote cursor", "顯示遠端游標"),
        ("Show quality monitor", "顯示質量監測"),
        ("Disable clipboard", "停用剪貼簿"),
        ("Lock after session end", "工作階段結束後鎖定電腦"),
        ("Insert", "插入"),
        ("Insert Lock", "鎖定遠端電腦"),
        ("Refresh", "重新載入"),
        ("ID does not exist", "ID 不存在"),
        ("Failed to connect to rendezvous server", "無法連接至 rendezvous 伺服器"),
        ("Please try later", "請稍候再試"),
        ("Remote desktop is offline", "遠端電腦離線"),
        ("Key mismatch", "金鑰不符"),
        ("Timeout", "逾時"),
        ("Failed to connect to relay server", "無法連接至轉送伺服器"),
        ("Failed to connect via rendezvous server", "無法透過 rendezvous 伺服器連接"),
        ("Failed to connect via relay server", "無法透過轉送伺服器連接"),
        ("Failed to make direct connection to remote desktop", "無法直接連線至遠端電腦"),
        ("Set Password", "設置密碼"),
        ("OS Password", "作業系統密碼"),
        ("install_tip", "UAC 會導致 RustDesk 在某些情況下無法正常以遠端電腦運作。若要避開 UAC，請點擊下方按鈕將 RustDesk 安裝到系統中。"),
        ("Click to upgrade", "點擊以升級"),
        ("Click to download", "點擊以下載"),
        ("Click to update", "點擊以更新"),
        ("Configure", "設定"),
        ("config_acc", "您需要授予 RustDesk ｢協助工具」 權限才能遠端存取電腦。"),
        ("config_screen", "您需要授予 RustDesk ｢畫面錄製」 權限才能遠端存取電腦。"),
        ("Installing ...", "正在安裝..."),
        ("Install", "安裝"),
        ("Installation", "安裝"),
        ("Installation Path", "安裝路徑"),
        ("Create start menu shortcuts", "建立開始選單捷徑"),
        ("Create desktop icon", "建立桌面圖示"),
        ("agreement_tip", "開始安裝即表示接受許可協議"),
        ("Accept and Install", "接受並安裝"),
        ("End-user license agreement", "使用者授權合約"),
        ("Generating ...", "正在產生 ..."),
        ("Your installation is lower version.", "您的安裝版本過舊。"),
        ("not_close_tcp_tip", "使用通道時請不要關閉此視窗"),
        ("Listening ...", "正在等待通道連接..."),
        ("Remote Host", "遠端主機"),
        ("Remote Port", "遠端連接埠"),
        ("Action", "操作"),
        ("Add", "新增"),
        ("Local Port", "本機連接埠"),
        ("Local Address", "本機地址"),
        ("Change Local Port", "修改本機連接埠"),
        ("setup_server_tip", "若您需要更快的連接速度，可以選擇自行建立伺服器"),
        ("Too short, at least 6 characters.", "過短，至少需 6 個字元。"),
        ("The confirmation is not identical.", "兩次輸入不相符"),
        ("Permissions", "權限"),
        ("Accept", "接受"),
        ("Dismiss", "關閉"),
        ("Disconnect", "斷開連線"),
        ("Allow using keyboard and mouse", "允許使用鍵盤和滑鼠"),
        ("Allow using clipboard", "允許使用剪貼簿"),
        ("Allow hearing sound", "允許分享音訊"),
        ("Allow file copy and paste", "允許文件複製和粘貼"),
        ("Connected", "已連接"),
        ("Direct and encrypted connection", "加密直接連線"),
        ("Relayed and encrypted connection", "加密轉送連線"),
        ("Direct and unencrypted connection", "未加密直接連線"),
        ("Relayed and unencrypted connection", "未加密轉送連線"),
        ("Enter Remote ID", "輸入遠端 ID"),
        ("Enter your password", "輸入您的密碼"),
        ("Logging in...", "正在登入..."),
        ("Enable RDP session sharing", "啟用 RDP 工作階段共享"),
        ("Auto Login", "自動登入 (鎖定將在設定關閉後套用)"),
        ("Enable Direct IP Access", "允許 IP 直接存取"),
        ("Rename", "重新命名"),
        ("Space", "空白"),
        ("Create Desktop Shortcut", "建立桌面捷徑"),
        ("Change Path", "更改路徑"),
        ("Create Folder", "建立資料夾"),
        ("Please enter the folder name", "請輸入資料夾名稱"),
        ("Fix it", "修復"),
        ("Warning", "警告"),
        ("Login screen using Wayland is not supported", "不支援使用 Wayland 的登入畫面"),
        ("Reboot required", "需要重新啟動"),
        ("Unsupported display server ", "不支援顯示伺服器"),
        ("x11 expected", "預期 x11"),
        ("Port", "端口"),
        ("Settings", "設定"),
        ("Username", "使用者名稱"),
        ("Invalid port", "連接埠無效"),
        ("Closed manually by the peer", "由對方手動關閉"),
        ("Enable remote configuration modification", "啟用遠端更改設定"),
        ("Run without install", "跳過安裝直接執行"),
        ("Always connected via relay", "一律透過轉送連線"),
        ("Always connect via relay", "一律透過轉送連線"),
        ("whitelist_tip", "只有白名單中的 IP 可以存取"),
        ("Login", "登入"),
        ("Verify", ""),
        ("Remember me", ""),
        ("Trust this device", ""),
        ("Verification code", ""),
        ("verification_tip", ""),
        ("Logout", "登出"),
        ("Tags", "標籤"),
        ("Search ID", "搜尋 ID"),
        ("Current Wayland display server is not supported", "目前不支援 Wayland 顯示伺服器"),
        ("whitelist_sep", "使用逗號、分號、空白，或是換行來分隔"),
        ("Add ID", "新增 ID"),
        ("Add Tag", "新增標籤"),
        ("Unselect all tags", "取消選取所有標籤"),
        ("Network error", "網路錯誤"),
        ("Username missed", "缺少使用者名稱"),
        ("Password missed", "缺少密碼"),
        ("Wrong credentials", "提供的登入資訊有誤"),
        ("Edit Tag", "編輯標籤"),
        ("Unremember Password", "忘掉密碼"),
        ("Favorites", "收藏"),
        ("Add to Favorites", "加入到收藏"),
        ("Remove from Favorites", "從收藏中刪除"),
        ("Empty", "空空如也"),
        ("Invalid folder name", "資料夾名稱無效"),
        ("Socks5 Proxy", "Socks5 代理"),
        ("Hostname", "主機名稱"),
        ("Discovered", "已發現"),
        ("install_daemon_tip", "為了開機啟動，請安裝系統服務。"),
        ("Remote ID", "遠端 ID"),
        ("Paste", "貼上"),
        ("Paste here?", "貼上到這裡?"),
        ("Are you sure to close the connection?", "您確定要關閉連線嗎？"),
        ("Download new version", "下載新版本"),
        ("Touch mode", "觸控模式"),
        ("Mouse mode", "滑鼠模式"),
        ("One-Finger Tap", "單指輕觸"),
        ("Left Mouse", "滑鼠左鍵"),
        ("One-Long Tap", "單指長按"),
        ("Two-Finger Tap", "雙指輕觸"),
        ("Right Mouse", "滑鼠右鍵"),
        ("One-Finger Move", "單指移動"),
        ("Double Tap & Move", "雙擊並移動"),
        ("Mouse Drag", "滑鼠選中拖動"),
        ("Three-Finger vertically", "三指垂直滑動"),
        ("Mouse Wheel", "滑鼠滾輪"),
        ("Two-Finger Move", "雙指移動"),
        ("Canvas Move", "移動畫布"),
        ("Pinch to Zoom", "雙指縮放"),
        ("Canvas Zoom", "縮放畫布"),
        ("Reset canvas", "重置畫布"),
        ("No permission of file transfer", "無文件傳輸權限"),
        ("Note", "備註"),
        ("Connection", "連接"),
        ("Share Screen", "共享畫面"),
        ("CLOSE", "關閉"),
        ("OPEN", "開啟"),
        ("Chat", "聊天消息"),
        ("Total", "總計"),
        ("items", "個項目"),
        ("Selected", "已選擇"),
        ("Screen Capture", "畫面錄製"),
        ("Input Control", "輸入控制"),
        ("Audio Capture", "音訊錄製"),
        ("File Connection", "檔案連線"),
        ("Screen Connection", "畫面連線"),
        ("Do you accept?", "是否接受？"),
        ("Open System Setting", "打開系統設定"),
        ("How to get Android input permission?", "如何獲取 Android 的輸入權限？"),
        ("android_input_permission_tip1", "取得輸入權限後可以讓遠端裝置通過滑鼠控制此 Android 裝置"),
        ("android_input_permission_tip2", "請在接下來的系統設定頁面中，找到並進入 ｢已安裝的服務｣ 頁面，並將 ｢RustDesk Input｣ 服務開啟"),
        ("android_new_connection_tip", "收到新的連接控制請求，對方想要控制您目前的設備"),
        ("android_service_will_start_tip", "開啟畫面錄製權限將自動開啟服務，允許其他裝置向此裝置請求建立連接。"),
        ("android_stop_service_tip", "關閉服務將自動關閉所有已建立的連接。"),
        ("android_version_audio_tip", "目前的 Android 版本不支持音訊錄製，請升級至 Android 10 或以上版本。"),
        ("android_start_service_tip", "點擊 ｢啟動服務｣ 或啟用 ｢畫面錄製｣ 權限以開啟手機畫面共享服務。"),
        ("Account", "賬戶"),
        ("Overwrite", "覆寫"),
        ("This file exists, skip or overwrite this file?", "此檔案/資料夾已存在，要跳過或是覆寫此檔案嗎？"),
        ("Quit", "退出"),
        ("doc_mac_permission", "https://rustdesk.com/docs/zh-tw/manual/mac/#啟用權限"),
        ("Help", "幫助"),
        ("Failed", "失敗"),
        ("Succeeded", "成功"),
        ("Someone turns on privacy mode, exit", "其他用戶開啟隱私模式，退出"),
        ("Unsupported", "不支持"),
        ("Peer denied", "被控端拒絕"),
        ("Please install plugins", "請安裝插件"),
        ("Peer exit", "被控端退出"),
        ("Failed to turn off", "退出失敗"),
        ("Turned off", "退出"),
        ("In privacy mode", "開啟隱私模式"),
        ("Out privacy mode", "退出隱私模式"),
        ("Language", "語言"),
        ("Keep RustDesk background service", "保持RustDesk後台服務"),
        ("Ignore Battery Optimizations", "忽略電池優化"),
        ("android_open_battery_optimizations_tip", "如需關閉此功能，請在接下來的RustDesk應用設置頁面中，找到並進入 [電源] 頁面，取消勾選 [不受限制]"),
        ("Connection not allowed", "對方不允許連接"),
        ("Legacy mode", "傳統模式"),
        ("Map mode", "1：1傳輸"),
        ("Translate mode", "翻譯模式"),
        ("Use permanent password", "使用固定密碼"),
        ("Use both passwords", "同時使用兩種密碼"),
        ("Set permanent password", "設定固定密碼"),
        ("Enable Remote Restart", "允許遠程重啓"),
        ("Allow remote restart", "允許遠程重啓"),
        ("Restart Remote Device", "重啓遠程電腦"),
        ("Are you sure you want to restart", "确定要重启"),
        ("Restarting Remote Device", "正在重啓遠程設備"),
        ("remote_restarting_tip", "遠程設備正在重啓，請關閉當前提示框，並在一段時間後使用永久密碼重新連接"),
        ("Copied", "已複製"),
        ("Exit Fullscreen", "退出全屏"),
        ("Fullscreen", "全屏"),
        ("Mobile Actions", "移動端操作"),
        ("Select Monitor", "選擇監視器"),
        ("Control Actions", "控制操作"),
        ("Display Settings", "顯示設置"),
        ("Ratio", "比例"),
        ("Image Quality", "畫質"),
        ("Scroll Style", "滾動樣式"),
        ("Show Menubar", "顯示菜單欄"),
        ("Hide Menubar", "隱藏菜單欄"),
        ("Direct Connection", "直接連接"),
        ("Relay Connection", "中繼連接"),
        ("Secure Connection", "安全連接"),
        ("Insecure Connection", "非安全連接"),
        ("Scale original", "原始尺寸"),
        ("Scale adaptive", "適應窗口"),
        ("General", "常規"),
        ("Security", "安全"),
        ("Theme", "主題"),
        ("Dark Theme", "暗黑主題"),
        ("Dark", "黑暗"),
        ("Light", "明亮"),
        ("Follow System", "跟隨系統"),
        ("Enable hardware codec", "使用硬件編解碼"),
        ("Unlock Security Settings", "解鎖安全設置"),
        ("Enable Audio", "允許傳輸音頻"),
        ("Unlock Network Settings", "解鎖網絡設置"),
        ("Server", "服務器"),
        ("Direct IP Access", "IP直接訪問"),
        ("Proxy", "代理"),
        ("Apply", "應用"),
        ("Disconnect all devices?", "斷開所有遠程連接?"),
        ("Clear", "清空"),
        ("Audio Input Device", "音頻輸入設備"),
        ("Deny remote access", "拒絕遠程訪問"),
        ("Use IP Whitelisting", "只允許白名單上的IP訪問"),
        ("Network", "網絡"),
        ("Enable RDP", "允許RDP訪問"),
        ("Pin menubar", "固定菜單欄"),
        ("Unpin menubar", "取消固定菜單欄"),
        ("Recording", "錄屏"),
        ("Directory", "目錄"),
        ("Automatically record incoming sessions", "自動錄製來訪會話"),
        ("Change", "變更"),
        ("Start session recording", "開始錄屏"),
        ("Stop session recording", "結束錄屏"),
        ("Enable Recording Session", "允許錄製會話"),
        ("Allow recording session", "允許錄製會話"),
        ("Enable LAN Discovery", "允許局域網發現"),
        ("Deny LAN Discovery", "拒絕局域網發現"),
        ("Write a message", "輸入聊天消息"),
        ("Prompt", "提示"),
        ("Please wait for confirmation of UAC...", "請等待對方確認UAC"),
        ("elevated_foreground_window_tip", "遠端桌面的當前窗口需要更高的權限才能操作, 暫時無法使用鼠標鍵盤, 可以請求對方最小化當前窗口, 或者在連接管理窗口點擊提升。為避免這個問題，建議在遠端設備上安裝本軟件。"),
        ("Disconnected", "會話已結束"),
        ("Other", "其他"),
        ("Confirm before closing multiple tabs", "關閉多個分頁前跟我確認"),
        ("Keyboard Settings", "鍵盤設置"),
        ("Full Access", "完全訪問"),
        ("Screen Share", "僅共享屏幕"),
        ("Wayland requires Ubuntu 21.04 or higher version.", "Wayland 需要 Ubuntu 21.04 或更高版本。"),
        ("Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.", "Wayland 需要更高版本的 linux 發行版。 請嘗試 X11 桌面或更改您的操作系統。"),
        ("JumpLink", "查看"),
        ("Please Select the screen to be shared(Operate on the peer side).", "請選擇要分享的畫面（在對端操作）。"),
        ("Show RustDesk", ""),
        ("This PC", ""),
        ("or", ""),
        ("Continue with", ""),
        ("Elevate", "提權"),
        ("Zoom cursor", ""),
        ("Accept sessions via password", "只允許密碼訪問"),
        ("Accept sessions via click", "只允許點擊訪問"),
        ("Accept sessions via both", "允許密碼或點擊訪問"),
        ("Please wait for the remote side to accept your session request...", "請等待對方接受你的連接..."),
        ("One-time Password", "一次性密碼"),
        ("Use one-time password", "使用一次性密碼"),
        ("One-time password length", "一次性密碼長度"),
        ("Request access to your device", "請求訪問你的設備"),
        ("Hide connection management window", "隱藏連接管理窗口"),
        ("hide_cm_tip", "在只允許密碼連接並且只用固定密碼的情況下才允許隱藏"),
        ("wayland_experiment_tip", ""),
        ("Right click to select tabs", "右鍵選擇選項卡"),
        ("Skipped", ""),
        ("Add to Address Book", "添加到地址簿"),
        ("Group", "小組"),
        ("Search", "搜索"),
        ("Closed manually by the web console", "被web控制台手動關閉"),
        ("Local keyboard type", "本地鍵盤類型"),
        ("Select local keyboard type", "請選擇本地鍵盤類型"),
        ("software_render_tip", "如果你使用英偉達顯卡, 並且遠程窗口在會話建立後會立刻關閉, 那麼安裝nouveau驅動並且選擇使用軟件渲染可能會有幫助。重啟軟件後生效。"),
        ("Always use software rendering", "使用軟件渲染"),
        ("config_input", ""),
        ("request_elevation_tip", "如果對面有人, 也可以請求提升權限。"),
        ("Wait", "等待"),
        ("Elevation Error", "提權失敗"),
        ("Ask the remote user for authentication", "請求遠端用戶授權"),
        ("Choose this if the remote account is administrator", "當對面電腦是管理員賬號時選擇該選項"),
        ("Transmit the username and password of administrator", "發送管理員賬號的用戶名密碼"),
        ("still_click_uac_tip", "依然需要被控端用戶在UAC窗口點擊確認。"),
        ("Request Elevation", "請求提權"),
        ("wait_accept_uac_tip", "請等待遠端用戶確認UAC對話框。"),
        ("Elevate successfully", "提權成功"),
        ("uppercase", "大寫字母"),
        ("lowercase", "小寫字母"),
        ("digit", "數字"),
        ("special character", "特殊字符"),
        ("length>=8", "長度不小於8"),
        ("Weak", "弱"),
        ("Medium", "中"),
        ("Strong", "強"),
        ("Switch Sides", ""),
        ("Please confirm if you want to share your desktop?", ""),
    ].iter().cloned().collect();
}
