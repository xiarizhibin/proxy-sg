# proxy-sg · HTTP(S) + SOCKS5 双协议代理

单进程 Node 服务，一个端口同时提供 **HTTP/HTTPS 正向代理（含 CONNECT）**，可选原生 **SOCKS5**，并带一条 **WSS 隧道**（给 PaaS 这种只暴露 443/TLS 的托管环境用，配套本地 `bridge.mjs` 转成本机 SOCKS5）。

- **强制 IPv4 出站**：`dns.setDefaultResultOrder('ipv4first')` + 所有 socket `family: 4`，不会落到 AAAA 记录。
- **认证**：HTTP 走 `Proxy-Authorization: Basic`，SOCKS5 走 RFC1929 用户名/密码，同一套 `PROXY_USER` / `PROXY_PASS`。
- **SSRF 卫生**：默认拒绝 localhost / 内网段 / 链路本地；`PRIVATE_ALLOW=true` 可关。
- **健康检查**：`GET /__health` 返回连接数、字节数、是否开了 SOCKS 与隧道。
- 零依赖运行时（只有 `ws`），Node ≥ 18。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 8080 | HTTP/HTTPS 代理端口（PaaS 会自动注入） |
| `SOCKS_PORT` | 空 | 原生 SOCKS5 端口，只在能裸 TCP 的环境（VPS/裸机）有效 |
| `PROXY_USER` | proxyuser | 用户名 |
| `PROXY_PASS` | proxypass | 密码 |
| `ENABLE_TUNNEL` | true | 是否开 `/__tunnel` WSS 隧道 |
| `PRIVATE_ALLOW` | false | 允许访问内网目标 |
| `CONNECT_TIMEOUT_MS` | 15000 | 建连超时 |

## 用法

### HTTPS 代理（CONNECT）

```bash
curl -x https://USER:PASS@HOST:443 https://ipinfo.io/json
# 或 http:// 前缀（同样是 CONNECT，只是到代理那一跳不加密）
curl -x http://USER:PASS@HOST:443 https://ipinfo.io/json
```

Python：

```python
import requests
p = "https://USER:PASS@HOST:443"
print(requests.get("https://ipinfo.io/json", proxies={"http": p, "https": p}, timeout=20).json())
```

### 原生 SOCKS5（需要裸 TCP：VPS / 裸机）

```bash
curl --socks5-hostname USER:PASS@HOST:1080 https://ipinfo.io/json
```

### PaaS（Render 等只给 443/TLS）上的 SOCKS5

外部客户端没法直接说 SOCKS5-over-TLS，用本地桥：

```bash
node bridge.mjs --host HOST --port 443 --listen 1080 --user USER --pass PASS
# 起来后，本机 127.0.0.1:1080 就是一个标准 SOCKS5
curl --socks5-hostname 127.0.0.1:1080 https://ipinfo.io/json
```

`bridge.mjs` 零依赖（手写 WS 帧），可选 `--via http://127.0.0.1:8080` 指定一个本地可用的 HTTP 代理去够到被墙的域名，`--plain` 用于 `ws://` 自测。

## 部署

Render：

1. New → Web Service → Public Git Repository → 填本仓库 URL
2. Language=Node，Build=`npm install`，Start=`npm start`
3. Region 选 **Singapore**
4. 环境变量加 `PROXY_USER` / `PROXY_PASS`
5. 免费档 15 分钟无流量会休眠，冷启动 ~50s；要常驻用付费档或 VPS

VPS：

```bash
PROXY_USER=u PROXY_PASS=p SOCKS_PORT=1080 PORT=8080 node server.js
```

## 自测

```bash
curl -s -o /dev/null -w '%{http_code}\n' -x http://USER:PASS@127.0.0.1:8080 https://www.gstatic.com/generate_204   # 期望 204
curl -s -o /dev/null -w '%{http_code}\n' --socks5-hostname USER:PASS@127.0.0.1:1080 https://www.gstatic.com/generate_204
curl -s http://127.0.0.1:8080/__health
```

## 许可

MIT
