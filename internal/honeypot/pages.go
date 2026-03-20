package honeypot

import (
	"net/http"
	"strings"
)

// serveFakePage returns a realistic-looking fake page to waste attacker time.
func serveFakePage(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")

	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "wp-login") || strings.Contains(lower, "wp-admin"):
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeWordPress))
	case strings.Contains(lower, "phpmyadmin"):
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakePHPMyAdmin))
	case strings.Contains(lower, ".env"):
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeEnv))
	case strings.Contains(lower, ".git"):
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeGitConfig))
	default:
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeAdmin))
	}
}

const fakeWordPress = `<!DOCTYPE html>
<html lang="en-US">
<head><title>Log In &lsaquo; Site &#8212; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}
#login{width:320px;margin:auto;padding:8% 0 0}#loginform{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px}
.login h1 a{background-image:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48L3N2Zz4=);width:84px;height:84px;display:block;margin:0 auto 25px}
input[type=text],input[type=password]{width:100%;padding:8px;margin:4px 0 16px;border:1px solid #8c8f94;border-radius:4px;font-size:24px}
input[type=submit]{background:#2271b1;border:1px solid #2271b1;color:#fff;padding:6px 12px;border-radius:4px;font-size:13px;cursor:pointer;width:100%}
</style></head>
<body class="login">
<div id="login"><h1><a href="#">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" size="20" autocapitalize="off" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" size="20" /></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p>
</form></div></body></html>`

const fakePHPMyAdmin = `<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{font-family:sans-serif;background:#e7e9ed;margin:0}
.header{background:#2962ff;color:#fff;padding:10px 20px;font-size:18px}
.content{padding:20px}
#loginform{background:#fff;padding:20px;border-radius:4px;max-width:400px;margin:40px auto;box-shadow:0 2px 4px rgba(0,0,0,.1)}
input{width:100%;padding:8px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
button{background:#2962ff;color:#fff;padding:10px;border:none;border-radius:4px;width:100%;cursor:pointer;font-size:14px}
</style></head>
<body><div class="header">phpMyAdmin 5.2.1</div>
<div class="content"><form id="loginform" method="post" action="/phpmyadmin/index.php">
<h3>Log in</h3>
<label>Username:</label><input type="text" name="pma_username" />
<label>Password:</label><input type="password" name="pma_password" />
<label>Server Choice:</label><input type="text" name="pma_servername" value="localhost" />
<button type="submit">Go</button>
</form></div></body></html>`

const fakeEnv = `APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:dGhpc2lzYWZha2VrZXlmb3Job25leXBvdA==
APP_DEBUG=false
APP_URL=https://example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app_user
DB_PASSWORD=s3cur3_p4ssw0rd_f4k3

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
`

const fakeGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/example/webapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`

const fakeAdmin = `<!DOCTYPE html>
<html><head><title>Admin Panel</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login-box{background:#16213e;padding:40px;border-radius:8px;box-shadow:0 4px 6px rgba(0,0,0,.3);width:360px}
h2{text-align:center;color:#0f3460;margin-bottom:30px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;border-radius:4px;background:#1a1a2e;color:#e0e0e0;box-sizing:border-box}
button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;margin-top:16px}
</style></head>
<body><div class="login-box">
<h2>Admin Panel</h2>
<form method="post" action="/admin/login">
<input type="text" name="username" placeholder="Username" />
<input type="password" name="password" placeholder="Password" />
<button type="submit">Login</button>
</form></div></body></html>`
