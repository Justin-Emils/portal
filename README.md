# 蓝旭控制台

一个单文件的门户（Python 标准库，无第三方依赖）：统一登录 + 服务导航 + 连接信息。

## 文件

| 文件 | 作用 |
|---|---|
| `portal.py` | 主程序：路由、登录、密码、连接信息 |
| `services.json` | 服务卡片列表（改这个就改门户内容，无需重启） |
| `credentials.json` | 连接信息（**不入库**，见 .gitignore） |
| `password.sha256` | 门户密码哈希（**不入库**） |
| `secret.key` | 会话签名密钥（**不入库**，删了等于所有人重新登录） |
| `credentials.example.json` | 连接信息的格式示例 |

## 路由

```
/            门户首页（未登录 → 登录页）
/login       登录提交
/logout      退出
/password    修改密码
/vault       连接信息（需二次验证，10 分钟有效）
/verify      nginx auth_request 子请求，返回 204/401
```

## 部署

```bash
# 依赖：python3（仅标准库）
systemctl status bx-portal          # 服务状态
systemctl restart bx-portal         # 改完 portal.py 后重启
journalctl -u bx-portal -n 50       # 看日志
```

nginx 通过 `auth_request /_portal_verify` 把其他端口（DSH、文件站等）的鉴权也接到这里，
实现「登录一次，全站通行」。

## 首次部署

```bash
cp credentials.example.json credentials.json   # 按实际填写
python3 -c "import hashlib;print(hashlib.sha256(b'你的密码').hexdigest())" > password.sha256
chmod 600 password.sha256 credentials.json
systemctl restart bx-portal
```

`secret.key` 会在首次启动时自动生成。
