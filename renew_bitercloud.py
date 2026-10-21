#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitercloud (https://dashboard.bitercloud.lat) 服务器全自动登录与续期脚本。
- 自动从网络池/自定义代理发起连接
- 使用账号密码自动登录，获取最新 Session 凭证
- 自动从 /servers 页面解析服务器 ID 与续期接口，无需手动配置 ID
- 向 PATCH /servers/{server_id}/renew 发起续期
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
SERVER_ID = os.environ.get("BITERCLOUD_SERVER_ID", "").strip()

TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()
TG_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
CUSTOM_PROXY = os.environ.get("CUSTOM_PROXY", "").strip()
SESSION_KEY = os.environ.get("BITERCLOUD_SESSION_KEY", "").strip()
STATE_FILE = "bitercloud_state.json"

BASE_URL = "https://dashboard.bitercloud.lat"
LOGIN_URL = f"{BASE_URL}/login"
SERVERS_URL = f"{BASE_URL}/servers"


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


def save_encrypted_cookies(state, cookies, proxy, s_id=""):
    if not SESSION_KEY or not cookies:
        return
    import json
    payload = json.dumps(cookies, separators=(",", ":"))
    state["encrypted_cookies"] = Fernet(SESSION_KEY.encode()).encrypt(payload.encode()).decode()
    state["last_proxy"] = proxy
    state["session_saved_time"] = now_str()
    if s_id:
        state["server_id"] = s_id


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
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Origin": BASE_URL,
        "Referer": SERVERS_URL,
    })
    for name, value in cookies.items():
        s.cookies.set(name, value, domain="dashboard.bitercloud.lat", path="/")
    xsrf = s.cookies.get("XSRF-TOKEN")
    if xsrf:
        s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)
    return s


def extract_server_renew_urls(html_text):
    """从 /servers 页面中自动解析出所有续期目标 URL 或 Server ID"""
    found = []
    # 匹配形如 /servers/{id}/renew
    matches = re.findall(r'[\'"](/servers/([^/\'"]+)/renew)[\'"]', html_text)
    for path, sid in matches:
        full_url = f"{BASE_URL}{path}" if path.startswith("/") else path
        if (full_url, sid) not in found:
            found.append((full_url, sid))

    # 匹配形如 action="https://dashboard.bitercloud.lat/servers/{id}/renew"
    full_matches = re.findall(r'action=[\'"](https?://[^/\'"]+/servers/([^/\'"]+)/renew)[\'"]', html_text)
    for full_url, sid in full_matches:
        if (full_url, sid) not in found:
            found.append((full_url, sid))

    # 兜底匹配：卡片中的特定属性，如 data-server-id="xxx"
    data_ids = re.findall(r'data-server(?:-id)?=[\'"]([a-zA-Z0-9_-]+)[\'"]', html_text)
    for sid in data_ids:
        renew_url = f"{BASE_URL}/servers/{sid}/renew"
        if (renew_url, sid) not in found:
            found.append((renew_url, sid))

    return found


def renew_with_saved_session(state):
    proxy = state.get("last_proxy", "")
    target_id = SERVER_ID or state.get("server_id", "")
    if not proxy:
        return False
    s = restore_cookies(state, proxy)
    if s is None:
        return False
    try:
        # 如果没有指定 target_id，先访问 /servers 获取页面
        if not target_id:
            res_servers = s.get(SERVERS_URL, timeout=10)
            if res_servers.status_code == 200:
                pairs = extract_server_renew_urls(res_servers.text)
                if pairs:
                    renew_url, target_id = pairs[0]
                else:
                    return False
            else:
                return False
        else:
            renew_url = f"{BASE_URL}/servers/{target_id}/renew"

        response = s.patch(renew_url, allow_redirects=False, timeout=15)
        log(f"♻️ 复用 Bitercloud 登录会话：PATCH {renew_url} -> HTTP {response.status_code}")
        if response.status_code in (200, 302):
            log(f"✅ Bitercloud 会话仍有效，服务器 ({target_id}) 续期成功！")
            state["last_renew_time"] = now_str()
            state["server_id"] = target_id
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

        # 2. 提交账号密码登录 (期望得到 302 重定向至 /home 或 /servers)
        r_post = s.post(LOGIN_URL, data=payload, allow_redirects=False, timeout=8)
        if r_post.status_code not in (200, 302) or r_post.headers.get("Location") == f"{BASE_URL}/blocked":
            return None

        # 重新同步登录后生成的最新防伪 Token
        new_xsrf = s.cookies.get("XSRF-TOKEN")
        if new_xsrf:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(new_xsrf)

        s.headers["Referer"] = SERVERS_URL

        # 3. 自动抓取 /servers 页面中的续期 URL 与 Server ID
        target_renew_url = f"{BASE_URL}/servers/{SERVER_ID}/renew" if SERVER_ID else None
        current_sid = SERVER_ID

        if not target_renew_url:
            r_servers = s.get(SERVERS_URL, timeout=8)
            if r_servers.status_code == 200:
                urls = extract_server_renew_urls(r_servers.text)
                if urls:
                    target_renew_url, current_sid = urls[0]
                else:
                    return None
            else:
                return None

        # 4. 发起 PATCH 续期请求
        s.headers["Accept"] = "application/json, text/html, */*"
        r_renew = s.patch(target_renew_url, allow_redirects=False, timeout=8)
        return (proxy, r_post.status_code, r_renew.status_code, r_renew.headers.get("Location"), target_renew_url, current_sid, s.cookies.get_dict())
    except Exception:
        return None


def main():
    log("=" * 50)
    log("⚡ Bitercloud 服务器自动登录续期启动")
    log(f"🕐 北京时间: {now_str()}")
    if SERVER_ID:
        log(f"🖥 指定服务器 ID: {SERVER_ID}")
    else:
        log("🖥 未配置服务器 ID，将自动从后台 /servers 页面解析提取")
    log("=" * 50)

    state = load_state()

    # 1. 优先复用上次加密保存的登录会话
    if renew_with_saved_session(state):
        send_tg("✅ Bitercloud 复用会话续期成功！")
        sys.exit(0)

    # 2. 账号密码全自动登录续期模式
    if USER and PASS:
        log(f"🔑 使用账号密码 ({USER[:3]}****) 进行全自动登录续期...")

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
                    proxy, post_status, renew_status, loc_hdr, renew_url, auto_sid, cookies = res
                    log(f"🎉 成功匹配可用代理节点 [{proxy}]！")
                    log(f"   步骤 1: 账号密码 POST 登录 -> 状态码 {post_status}")
                    log(f"   步骤 2: 自动解析到续期地址 -> {renew_url} (ID: {auto_sid})")
                    log(f"   步骤 3: 发起 PATCH 续期请求 -> 状态码 {renew_status}")
                    log(f"   步骤 4: 续期返回跳转 -> Location: {loc_hdr}")

                    if renew_status in (200, 302):
                        msg = (f"🎉 Bitercloud 服务器 ({auto_sid or 'Default'}) 续期成功！\n"
                               f"📌 节点: {proxy}\n"
                               f"🔑 登录状态: {post_status}\n"
                               f"🔄 续期状态: {renew_status} -> {loc_hdr or 'Success'}")
                        log(msg)
                        send_tg(msg)
                        save_encrypted_cookies(state, cookies, proxy, auto_sid)
                        state["last_renew_time"] = now_str()
                        save_state(state)
                        success = True
                        break

        if success:
            sys.exit(0)
        else:
            msg = "❌ Bitercloud 自动续期失败：未找到有效代理节点或未能获取续期接口。"
            log(msg)
            send_tg(msg)
            sys.exit(1)
    else:
        log("❌ 缺失配置：请提供 BITERCLOUD_USER 与 BITERCLOUD_PASS。")
        sys.exit(1)


if __name__ == "__main__":
    main()
