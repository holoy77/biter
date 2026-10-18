#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitercloud (https://dashboard.bitercloud.lat) 服务器全自动登录与续期脚本。
- 自动从网络池轮询可用代理节点绕过网关封锁 (/blocked)
- 使用账号密码自动登录，获取最新 Session 凭证
- 自动向 PATCH /servers/{server_id}/renew 接口发起续期请求
"""
import os
import sys
import re
import time
import datetime
import urllib.parse
import concurrent.futures
import requests
from cryptography.fernet import Fernet, InvalidToken

USER = os.environ.get("BITERCLOUD_USER", "").strip()
PASS = os.environ.get("BITERCLOUD_PASS", "").strip()
COOKIE = os.environ.get("BITERCLOUD_COOKIE", "").strip()
SERVER_ID = (os.environ.get("BITERCLOUD_SERVER_ID") or "Oh1vni0cCpJ1GHW-4qZMj").strip()

TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()
TG_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
CUSTOM_PROXY = os.environ.get("CUSTOM_PROXY", "").strip()
SESSION_KEY = os.environ.get("BITERCLOUD_SESSION_KEY", "").strip()
STATE_FILE = "bitercloud_state.json"

BASE_URL = "https://dashboard.bitercloud.lat"
LOGIN_URL = f"{BASE_URL}/login"
SERVERS_URL = f"{BASE_URL}/servers"
RENEW_URL = f"{BASE_URL}/servers/{SERVER_ID}/renew"


def log(*args):
    print(" ".join(str(arg) for arg in args), flush=True)


def now_str():
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    bj_now = utc_now + datetime.timedelta(hours=8)
    return bj_now.strftime('%Y-%m-%d %H:%M:%S')


def send_tg(msg):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": msg},
            timeout=10,
        )
    except Exception as e:
        log(f"⚠️ Telegram 通知发送失败：{e}")


def get_public_proxies():
    log("🌐 正在获取公共代理节点列表...")
    proxy_sources = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
    ]
    proxies = []
    for url in proxy_sources:
        try:
            r = requests.get(url, timeout=5)
            lines = [l.strip() for l in r.text.strip().splitlines() if l.strip()]
            for line in lines:
                if "socks" not in line and "http" not in line:
                    prefix = "socks5://" if "socks5" in url else "http://"
                    proxies.append(f"{prefix}{line}")
                else:
                    proxies.append(line)
        except Exception:
            pass
    return list(dict.fromkeys(proxies))


def load_state():
    try:
        import json
        with open(STATE_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def save_state(data):
    import json
    temporary = STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.replace(temporary, STATE_FILE)


def save_encrypted_cookies(state, cookies, proxy):
    if not SESSION_KEY or not cookies:
        return
    import json
    payload = json.dumps(cookies, separators=(",", ":"))
    state["encrypted_cookies"] = Fernet(SESSION_KEY.encode()).encrypt(payload.encode()).decode()
    state["last_proxy"] = proxy
    state["session_saved_time"] = now_str()


def restore_cookies(state, proxy):
    encrypted = state.get("encrypted_cookies")
    if not encrypted or not SESSION_KEY:
        return None
    import json
    try:
        cookies = json.loads(Fernet(SESSION_KEY.encode()).decrypt(encrypted.encode()).decode())
    except (InvalidToken, ValueError, TypeError):
        return None
    s = requests.Session()
    s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Origin": BASE_URL,
        "Referer": SERVERS_URL,
    })
    for name, value in cookies.items():
        s.cookies.set(name, value, domain="dashboard.bitercloud.lat", path="/")
    xsrf = s.cookies.get("XSRF-TOKEN")
    if xsrf:
        s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)
    return s


def renew_with_saved_session(state):
    proxy = state.get("last_proxy", "")
    if not proxy:
        return False
    s = restore_cookies(state, proxy)
    if s is None:
        return False
    try:
        response = s.patch(RENEW_URL, allow_redirects=False, timeout=15)
        log(f"♻️ 复用 Bitercloud 登录会话：PATCH 续期 -> HTTP {response.status_code}")
        if response.status_code in (200, 302):
            log("✅ Bitercloud 会话仍有效，本次不重新账号密码登录")
            state["last_renew_time"] = now_str()
            save_state(state)
            return True
    except Exception as exc:
        log(f"⚠️ 已保存 Bitercloud 会话不可用：{type(exc).__name__}")
    return False


def try_login_and_renew_via_proxy(proxy):
    s = requests.Session()
    s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8"
    })

    try:
        # 1. 打开登录页面并提取 CSRF _token
        r_get = s.get(LOGIN_URL, allow_redirects=False, timeout=5)
        if r_get.status_code != 200:
            return None

        tokens = re.findall(r'name="_token"\s+value="([^"]+)"', r_get.text)
        token_val = tokens[0] if tokens else ""

        xsrf_raw = s.cookies.get("XSRF-TOKEN")
        if xsrf_raw:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf_raw)

        payload = {"_token": token_val, "email": USER, "password": PASS}

        # 2. 提交账号密码登录 (期望得到 302 重定向至 /home)
        r_post = s.post(LOGIN_URL, data=payload, allow_redirects=False, timeout=8)
        if r_post.status_code not in (200, 302) or r_post.headers.get("Location") == f"{BASE_URL}/blocked":
            return None

        # 重新同步登录后生成的最新防伪 Token
        new_xsrf = s.cookies.get("XSRF-TOKEN")
        if new_xsrf:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(new_xsrf)

        s.headers["Accept"] = "application/json, text/html, */*"
        s.headers["Referer"] = SERVERS_URL

        # 3. 发起 PATCH 续期请求 (Laravel 成功后会返回 302 Redirect 并带 Alert 提示)
        r_renew = s.patch(RENEW_URL, allow_redirects=False, timeout=8)
        return (proxy, r_post.status_code, r_renew.status_code, r_renew.headers.get("Location"), r_renew.text, s.cookies.get_dict())
    except Exception:
        return None


def main():
    log("=" * 50)
    log("⚡ Bitercloud 服务器自动登录续期启动")
    log(f"🕐 北京时间: {now_str()}")
    log(f"🖥 服务器 ID: {SERVER_ID}")
    log("=" * 50)
    state = load_state()

    # 1. 优先复用上次加密保存的登录会话；失效才进入账号密码流程。
    if renew_with_saved_session(state):
        send_tg(f"✅ Bitercloud 复用会话续期成功（{SERVER_ID}）")
        sys.exit(0)

    # 2. 兼容手工 COOKIE 模式（如有）
    if COOKIE:
        log("🍪 方式 1: 使用已配置的 BITERCLOUD_COOKIE 发起续期...")
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": BASE_URL,
            "Referer": SERVERS_URL,
            "Cookie": COOKIE
        })
        xsrf_token = None
        for item in COOKIE.split(";"):
            if "XSRF-TOKEN=" in item:
                xsrf_token = item.split("XSRF-TOKEN=", 1)[-1].strip()
                break
        if xsrf_token:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf_token)

        try:
            resp = s.patch(RENEW_URL, allow_redirects=False, timeout=20)
            log(f"HTTP Status: {resp.status_code}, Location: {resp.headers.get('Location')}")
            if resp.status_code in (200, 302):
                msg = f"🎉 Bitercloud 服务器 ({SERVER_ID}) Cookie 模式续期成功！"
                log(msg)
                send_tg(msg)
                sys.exit(0)
            else:
                log("⚠️ Cookie 模式未通过，自动切换至账号密码全自动登录模式...")
        except Exception as e:
            log(f"⚠️ Cookie 模式执行异常: {e}")

    # 2. 账号密码全自动登录续期模式
    if USER and PASS:
        log(f"🔑 方式 2: 使用账号密码 ({USER[:3]}****) 进行全自动登录续期...")

        proxy_list = []
        if CUSTOM_PROXY:
            proxy_list.append(CUSTOM_PROXY)

        proxy_list.extend(get_public_proxies()[:300])

        log(f"🔍 正在并发轮询可用网络节点（池大小: {len(proxy_list)}）...")
        success = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(try_login_and_renew_via_proxy, proxy_list)
            for res in results:
                if res:
                    proxy, post_status, renew_status, loc_hdr, body, cookies = res
                    log(f"🎉 成功匹配可用代理节点 [{proxy}]！")
                    log(f"   步骤 1: 账号密码 POST 登录 -> 状态码 {post_status}")
                    log(f"   步骤 2: 发起 PATCH 续期请求 ({RENEW_URL}) -> 状态码 {renew_status}")
                    log(f"   步骤 3: 续期返回跳转 -> Location: {loc_hdr}")

                    if renew_status in (200, 302):
                        msg = (f"🎉 Bitercloud 服务器 ({SERVER_ID}) 全自动登录与续期成功！\n"
                               f"📌 节点: {proxy}\n"
                               f"🔑 登录状态: {post_status}\n"
                               f"🔄 续期状态: {renew_status} -> {loc_hdr or 'Success'}")
                        log(msg)
                        send_tg(msg)
                        save_encrypted_cookies(state, cookies, proxy)
                        state["last_renew_time"] = now_str()
                        save_state(state)
                        success = True
                        break

        if success:
            sys.exit(0)
        else:
            msg = "❌ Bitercloud 自动续期失败：未找到有效代理节点。"
            log(msg)
            send_tg(msg)
            sys.exit(1)
    else:
        log("❌ 缺失配置：请提供 BITERCLOUD_USER / BITERCLOUD_PASS 或 BITERCLOUD_COOKIE。")
        sys.exit(1)


if __name__ == "__main__":
    main()
