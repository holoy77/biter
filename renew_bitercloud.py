#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitercloud (https://dashboard.bitercloud.lat) 全自动登录与续期脚本
- 优先直连自定义代理 CUSTOM_PROXY 并输出详细排查日志
- 自动抓取 CtrlPanel /servers 页面中的服务器 ID 与续期表单
- 自动提取并提交 CSRF Token
"""
import os
import sys
import re
import datetime
import urllib.parse
import concurrent.futures
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


def log(*args):
    print(" ".join(str(arg) for arg in args), flush=True)


def now_str():
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    bj_now = utc_now + datetime.timedelta(hours=8)
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
        "Origin": BASE_URL,
        "Referer": SERVERS_URL,
    })
    for name, value in cookies.items():
        s.cookies.set(name, value, domain="dashboard.bitercloud.lat", path="/")
    xsrf = s.cookies.get("XSRF-TOKEN")
    if xsrf:
        s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)
    return s


def parse_renew_targets(html_text):
    """从 HTML 页面中解析续期 URL、服务器 ID 及提交方式"""
    results = []

    # 1. 查找包含 renew 的 form 表单及其 action
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

    # 2. 如果没找到完整 form，通过正则抓取 /servers/{id}/renew
    if not results:
        direct_matches = re.findall(r'(/servers/([a-zA-Z0-9_-]+)/renew)', html_text)
        for path, sid in direct_matches:
            url = urllib.parse.urljoin(BASE_URL, path)
            results.append({"url": url, "server_id": sid, "method": "POST", "token": ""})

    # 3. 兜底：抓取卡片或按钮里的 server ID
    if not results:
        raw_ids = re.findall(r'/servers/([a-zA-Z0-9_-]{5,})', html_text)
        for sid in set(raw_ids):
            if sid not in ("create", "databases", "edit"):
                results.append({"url": f"{BASE_URL}/servers/{sid}/renew", "server_id": sid, "method": "POST", "token": ""})

    return results


def execute_renew(session, target):
    """执行续期请求，支持 POST 与 PATCH 双向尝试"""
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

    # 方式 A: POST 带 _method 字段
    payload = {"_token": token, "_method": target.get("method", "POST")}
    r = session.post(url, data=payload, headers=headers, allow_redirects=False, timeout=12)
    log(f"   -> 尝试续期提交 (POST): HTTP {r.status_code}, Location: {r.headers.get('Location')}")

    if r.status_code in (200, 302):
        return True, r.status_code, r.headers.get("Location")

    # 方式 B: 直接 PATCH
    payload_patch = {"_token": token}
    r_patch = session.patch(url, data=payload_patch, headers=headers, allow_redirects=False, timeout=12)
    log(f"   -> 尝试续期提交 (PATCH): HTTP {r_patch.status_code}, Location: {r_patch.headers.get('Location')}")
    if r_patch.status_code in (200, 302):
        return True, r_patch.status_code, r_patch.headers.get("Location")

    return False, r.status_code, None


def attempt_login_and_renew(proxy, is_custom=False):
    prefix = "[自定义代理]" if is_custom else "[公共代理]"
    s = requests.Session()
    s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8"
    })

    try:
        # 1. 打开登录页面
        log(f"{prefix} 正在请求登录页: {LOGIN_URL} ...")
        r_get = s.get(LOGIN_URL, allow_redirects=False, timeout=12)
        log(f"{prefix} 登录页响应: HTTP {r_get.status_code}")

        if r_get.status_code == 403 or "blocked" in r_get.text.lower():
            log(f"{prefix} 该节点被 BiterCloud 网关拦截 (Blocked/403)")
            return None

        if r_get.status_code != 200:
            return None

        token_match = re.search(r'name="_token"\s+value="([^"]+)"', r_get.text)
        token_val = token_match.group(1) if token_match else ""

        xsrf = s.cookies.get("XSRF-TOKEN")
        if xsrf:
            s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)

        # 2. 提交登录
        payload = {"_token": token_val, "email": USER, "password": PASS}
        log(f"{prefix} 正在提交账号密码登录...")
        r_post = s.post(LOGIN_URL, data=payload, allow_redirects=False, timeout=12)
        loc = r_post.headers.get("Location", "")
        log(f"{prefix} 登录响应: HTTP {r_post.status_code}, 跳转目标: {loc}")

        if r_post.status_code not in (200, 302) or f"{BASE_URL}/blocked" in loc:
            log(f"{prefix} 登录失败或凭据错误。")
            return None

        # 3. 获取服务器列表并解析
        log(f"{prefix} 正在打开服务器控制台 ({SERVERS_URL}) 查找服务器...")
        r_servers = s.get(SERVERS_URL, timeout=12)
        if r_servers.status_code != 200:
            log(f"{prefix} 无法打开 /servers 页面，HTTP {r_servers.status_code}")
            return None

        targets = parse_renew_targets(r_servers.text)
        if not targets:
            log(f"{prefix} 未能在控制台页面中解析到续期按钮或服务器 ID！")
            return None

        target = targets[0]
        log(f"{prefix} 成功识别到服务器 ID: {target['server_id']}，续期地址: {target['url']}")

        # 4. 执行续期
        ok, status, redir = execute_renew(s, target)
        if ok:
            return {
                "proxy": proxy,
                "server_id": target["server_id"],
                "status": status,
                "location": redir,
                "cookies": s.cookies.get_dict(),
            }
        else:
            log(f"{prefix} 续期接口返回失败。")
            return None

    except Exception as exc:
        log(f"{prefix} 请求异常: {type(exc).__name__} - {exc}")
        return None


def get_public_proxies():
    sources = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ]
    proxies = []
    for url in sources:
        try:
            r = requests.get(url, timeout=5)
            for line in r.text.splitlines():
                line = line.strip()
                if line:
                    proxies.append(line if "socks" in line else f"socks5://{line}")
        except Exception:
            pass
    return list(dict.fromkeys(proxies))


def main():
    log("=" * 50)
    log("⚡ Bitercloud 全自动登录与续期运行开始")
    log(f"🕐 北京时间: {now_str()}")
    log("=" * 50)

    state = load_state()

    # 1. 如果有配置自定义代理，优先单独测试该代理
    if CUSTOM_PROXY:
        log(f"🎯 检测到已配置 CUSTOM_PROXY，优先进行专用通道测试...")
        res = attempt_login_and_renew(CUSTOM_PROXY, is_custom=True)
        if res:
            msg = (f"🎉 Bitercloud 服务器 ({res['server_id']}) 自动续期成功！\n"
                   f"📌 通道: 自定义代理\n"
                   f"🔄 状态: HTTP {res['status']}")
            log(msg)
            send_tg(msg)
            save_encrypted_cookies(state, res["cookies"], CUSTOM_PROXY, res["server_id"])
            state["last_renew_time"] = now_str()
            save_state(state)
            sys.exit(0)
        else:
            log("⚠️ 自定义代理专用测试未成功，准备尝试公共备选节点池...")

    # 2. 如果自定义代理失败或未配置，轮询备选池
    public_pool = get_public_proxies()[:200]
    log(f"🔍 开始并发测试公共节点池 (池大小: {len(public_pool)})...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(attempt_login_and_renew, p, False): p for p in public_pool}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                msg = (f"🎉 Bitercloud 服务器 ({res['server_id']}) 自动续期成功！\n"
                       f"📌 通道: {res['proxy']}\n"
                       f"🔄 状态: HTTP {res['status']}")
                log(msg)
                send_tg(msg)
                save_encrypted_cookies(state, res["cookies"], res["proxy"], res["server_id"])
                state["last_renew_time"] = now_str()
                save_state(state)
                sys.exit(0)

    log("❌ 所有代理通道均尝试失败。")
    send_tg("❌ Bitercloud 自动续期失败：未找到有效节点或续期接口未响应。")
    sys.exit(1)


if __name__ == "__main__":
    main()
