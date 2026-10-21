#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitercloud (https://dashboard.bitercloud.lat) 全自动登录与续期脚本
- 经由 Hysteria 2 (127.0.0.1:10809) 通道转发
- 优先使用 BITERCLOUD_COOKIE 绕过登录页 Cloudflare Turnstile 验证
- 自动提取 /servers 页面中的服务器 ID 与续期表单并提交
"""
import os
import sys
import re
import datetime
import urllib.parse
import requests
from cryptography.fernet import Fernet, InvalidToken

USER = os.environ.get("BITERCLOUD_USER", "").strip()
PASS = os.environ.get("BITERCLOUD_PASS", "").strip()
COOKIE = os.environ.get("BITERCLOUD_COOKIE", "").strip()
SERVER_ID = os.environ.get("BITERCLOUD_SERVER_ID", "").strip()
CUSTOM_PROXY = os.environ.get("CUSTOM_PROXY", "").strip()

TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()
TG_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
SESSION_KEY = os.environ.get("BITERCLOUD_SESSION_KEY", "").strip()
STATE_FILE = "bitercloud_state.json"

BASE_URL = "https://dashboard.bitercloud.lat"
LOGIN_URL = f"{BASE_URL}/login"
SERVERS_URL = f"{BASE_URL}/servers"
HY2_LOCAL_PROXY = "http://127.0.0.1:10809"


def log(*args):
    print(" ".join(str(arg) for arg in args), flush=True)


def now_str():
    utc_now = datetime.timezone.utc
    bj_now = datetime.datetime.now(utc_now) + datetime.timedelta(hours=8)
    return bj_now.strftime("%Y-%m-%d %H:%M:%S")


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
        log(f"⚠️ Telegram 发送失败：{e}")


def load_state():
    try:
        import json
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(data):
    import json
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


def save_encrypted_cookies(state, cookies, s_id=""):
    if not SESSION_KEY or not cookies:
        return
    import json
    payload = json.dumps(cookies, separators=(",", ":"))
    state["encrypted_cookies"] = Fernet(SESSION_KEY.encode()).encrypt(payload.encode()).decode()
    state["session_saved_time"] = now_str()
    if s_id:
        state["server_id"] = s_id


def build_session():
    s = requests.Session()
    if CUSTOM_PROXY:
        s.proxies = {"http": HY2_LOCAL_PROXY, "https": HY2_LOCAL_PROXY}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    })
    return s


def parse_renew_targets(html_text):
    results = []
    # 匹配含有 renew 的 form 表单
    forms = re.findall(r'<form[^>]+action=[\'"]([^\'"]*servers/[^\'"]+/renew[^\'"]*)[\'"][^>]*>(.*?)</form>', html_text, re.DOTALL | re.IGNORECASE)
    for action, form_body in forms:
        url = urllib.parse.urljoin(BASE_URL, action)
        sid_match = re.search(r'/servers/([^/]+)/renew', url)
        sid = sid_match.group(1) if sid_match else ""
        method_match = re.search(r'name=["\']_method["\']\s+value=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "POST"
        token_match = re.search(r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        token = token_match.group(1) if token_match else ""
        results.append({"url": url, "server_id": sid, "method": method, "token": token})

    # 匹配 /servers/{id}/renew
    if not results:
        direct_matches = re.findall(r'(/servers/([a-zA-Z0-9_-]+)/renew)', html_text)
        for path, sid in direct_matches:
            url = urllib.parse.urljoin(BASE_URL, path)
            results.append({"url": url, "server_id": sid, "method": "POST", "token": ""})

    # 兜底匹配卡片 ID
    if not results:
        raw_ids = re.findall(r'/servers/([a-zA-Z0-9_-]{5,})', html_text)
        for sid in set(raw_ids):
            if sid not in ("create", "databases", "edit"):
                results.append({"url": f"{BASE_URL}/servers/{sid}/renew", "server_id": sid, "method": "POST", "token": ""})

    return results


def execute_renew(session, target):
    url = target["url"]
    token = target.get("token") or ""
    if not token:
        xsrf = session.cookies.get("XSRF-TOKEN")
        token = urllib.parse.unquote(xsrf) if xsrf else ""

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Referer": SERVERS_URL,
        "Origin": BASE_URL,
    }
    if session.cookies.get("XSRF-TOKEN"):
        headers["X-XSRF-TOKEN"] = urllib.parse.unquote(session.cookies.get("XSRF-TOKEN"))

    # 方式 1: POST 表单携带 _method
    payload = {"_token": token, "_method": target.get("method", "POST")}
    r = session.post(url, data=payload, headers=headers, allow_redirects=False, timeout=12)
    log(f"   -> 提交续期请求 (POST): HTTP {r.status_code}, 跳转: {r.headers.get('Location')}")
    if r.status_code in (200, 302):
        return True, r.status_code, r.headers.get("Location")

    # 方式 2: PATCH 请求
    payload_patch = {"_token": token}
    r_patch = session.patch(url, data=payload_patch, headers=headers, allow_redirects=False, timeout=12)
    log(f"   -> 提交续期请求 (PATCH): HTTP {r_patch.status_code}, 跳转: {r_patch.headers.get('Location')}")
    if r_patch.status_code in (200, 302):
        return True, r_patch.status_code, r_patch.headers.get("Location")

    return False, r.status_code, None


def run_with_cookie(cookie_str):
    """直接使用 Cookie 续期"""
    log("🍪 正在尝试使用配置的 BITERCLOUD_COOKIE 发起续期...")
    s = build_session()

    # 注入 cookie 字符串
    for item in cookie_str.split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            s.cookies.set(k.strip(), v.strip(), domain="dashboard.bitercloud.lat", path="/")

    xsrf = s.cookies.get("XSRF-TOKEN")
    if xsrf:
        s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)

    # 校验控制台
    r_servers = s.get(SERVERS_URL, timeout=15)
    if r_servers.status_code != 200 or "/login" in r_servers.url:
        log("⚠️ Cookie 已失效或未能直接打开 /servers 页面。")
        return False

    targets = parse_renew_targets(r_servers.text)
    if not targets:
        log("❌ 未在 /servers 页面中找到续期表单或服务器。")
        return False

    target = targets[0]
    log(f"🎉 成功识别到服务器 ID: {target['server_id']}，续期地址: {target['url']}")

    ok, status, redir = execute_renew(s, target)
    if ok:
        msg = (f"🎉 Bitercloud 服务器 ({target['server_id']}) Cookie 模式续期成功！\n"
               f"📌 节点: Hysteria 2\n"
               f"🔄 状态: HTTP {status} -> {redir or 'Success'}")
        log(msg)
        send_tg(msg)
        return True
    return False


def main():
    log("=" * 50)
    log("⚡ Bitercloud 服务器自动登录续期启动")
    log(f"🕐 北京时间: {now_str()}")
    if CUSTOM_PROXY:
        log("🚀 代理通道: Hysteria 2 (127.0.0.1:10809)")
    log("=" * 50)

    # 优先走 Cookie 模式以避开 Turnstile
    if COOKIE:
        if run_with_cookie(COOKIE):
            sys.exit(0)
        else:
            log("⚠️ 尝试使用账号密码登录...")

    if not (USER and PASS):
        log("❌ 缺少有效 Cookie 且未配置账号密码，退出。")
        sys.exit(1)

    s = build_session()

    try:
        log(f"🌐 正在请求登录页: {LOGIN_URL} ...")
        r_get = s.get(LOGIN_URL, allow_redirects=False, timeout=15)
        log(f"   登录页响应: HTTP {r_get.status_code}")

        token_match = re.search(r'name="_token"\s+value="([^"]+)"', r_get.text)
        token_val = token_match.group(1) if token_match else ""

        xsrf = s.cookies.get("XSRF-TOKEN")
        if xsrf:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)

        payload = {
            "_token": token_val,
            "email": USER,
            "password": PASS,
            "remember": "on"
        }
        s.headers["Referer"] = LOGIN_URL
        s.headers["Origin"] = BASE_URL
        log("🔑 正在提交登录凭据...")
        r_post = s.post(LOGIN_URL, data=payload, allow_redirects=False, timeout=15)
        loc = r_post.headers.get("Location", "")
        log(f"   登录接口响应: HTTP {r_post.status_code}, 跳转目标: {loc}")

        if loc.endswith("/login") or r_post.status_code == 200:
            r_err = s.get(LOGIN_URL, timeout=10)
            err_box = re.findall(r'class="[^"]*(?:alert|invalid-feedback|error)[^"]*"[^>]*>(.*?)</div>', r_err.text, re.DOTALL)
            clean_err = re.sub(r'<[^>]+>', '', err_box[0]).strip() if err_box else "凭证错误或被 Turnstile 拦截"
            log(f"❌ 登录被拒绝: {clean_err}")
            if "cf-turnstile-response" in clean_err:
                log("👉 官网启用了 Cloudflare Turnstile 验证码，请在 GitHub Secrets 中配置 BITERCLOUD_COOKIE 绕过登录页。")
            sys.exit(1)

        log(f"🖥 正在获取服务器列表: {SERVERS_URL} ...")
        s.headers["Referer"] = loc or BASE_URL
        r_servers = s.get(SERVERS_URL, timeout=15)
        targets = parse_renew_targets(r_servers.text)
        if not targets:
            log("❌ 未在 /servers 页面中提取到续期按钮或服务器 ID！")
            sys.exit(1)

        target = targets[0]
        ok, status, redir = execute_renew(s, target)
        if ok:
            msg = (f"🎉 Bitercloud 服务器 ({target['server_id']}) 续期成功！\n"
                   f"📌 节点: Hysteria 2\n"
                   f"🔄 状态: HTTP {status} -> {redir or 'Success'}")
            log(msg)
            send_tg(msg)
            sys.exit(0)
        else:
            log(f"❌ 续期接口返回异常，HTTP 状态: {status}")
            sys.exit(1)

    except Exception as exc:
        log(f"❌ 运行异常: {type(exc).__name__} - {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
