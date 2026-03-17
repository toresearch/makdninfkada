import asyncio
import base64
import json
import os
import random
import re
import sys
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

TARGET_URL = os.environ.get("TARGET_URL", "").strip()
SCAN_ID = os.environ.get("SCAN_ID", "").strip()

PROGRESS_STAGES = [
    "identity_built",
    "browser_launched",
    "page_loaded",
    "screenshot_captured",
    "js_extracted",
    "endpoints_discovered",
    "network_analyzed",
    "complete",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) OPR/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Vivaldi/6.6.3271.61 Chrome/122.0.0.0 Safari/537.36",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1280, "height": 720},
    {"width": 1600, "height": 900},
]

LOCALES = ["en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "it-IT", "ja-JP", "pt-BR"]
TIMEZONES = [
    "America/New_York",
    "America/Los_Angeles",
    "Europe/London",
    "Europe/Paris",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Australia/Sydney",
    "America/Toronto",
]


def normalize_url(raw_value, base_url):
    if not raw_value:
        return ""
    value = str(raw_value).strip()
    if not value:
        return ""
    if value.startswith("javascript:") or value.startswith("data:") or value.startswith("mailto:") or value.startswith("tel:"):
        return ""
    return urljoin(base_url, value)


def dedupe_dict_list(items, key_fields):
    seen = set()
    out = []
    for item in items:
        key = tuple(item.get(k, "") for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def domain_split(urls, base_host):
    internal = []
    third_party = []
    for u in urls:
        parsed = urlparse(u.get("url", ""))
        if not parsed.netloc:
            continue
        if parsed.netloc == base_host:
            internal.append(u)
        else:
            third_party.append(u)
    return internal, third_party


def extract_json_object(text):
    if not text:
        return None
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def get_progress_url(callback_url):
    if "/api/callback/" in callback_url:
        return callback_url.replace("/api/callback/", "/api/progress/")
    if "/callback/" in callback_url:
        return callback_url.replace("/callback/", "/progress/")
    return callback_url


def classify_confidence(pattern_name):
    if pattern_name in {"fetch", "xhr_open", "axios", "jquery"}:
        return "high"
    if pattern_name in {"path_literal", "template_literal"}:
        return "medium"
    return "low"


def build_browser_headers(user_agent, locale):
    platform = "Windows"
    if "Macintosh" in user_agent:
        platform = "macOS"
    if "Linux" in user_agent and "Android" not in user_agent:
        platform = "Linux"
    if "Android" in user_agent:
        platform = "Android"
    if "iPhone" in user_agent:
        platform = "iOS"
    mobile = "?1" if "Mobile" in user_agent or "Android" in user_agent or "iPhone" in user_agent else "?0"
    if "Firefox" in user_agent:
        sec_ch = '"Not.A/Brand";v="99", "Firefox";v="123"'
    elif "Edg/" in user_agent:
        sec_ch = '"Not.A/Brand";v="99", "Microsoft Edge";v="122", "Chromium";v="122"'
    elif "OPR/" in user_agent:
        sec_ch = '"Not.A/Brand";v="99", "Opera";v="108", "Chromium";v="122"'
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        sec_ch = '"Not.A/Brand";v="99", "Safari";v="17"'
    else:
        sec_ch = '"Not.A/Brand";v="99", "Google Chrome";v="122", "Chromium";v="122"'
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": f"{locale},en;q=0.9",
        "Cache-Control": "max-age=0",
        "DNT": "1",
        "Sec-CH-UA": sec_ch,
        "Sec-CH-UA-Mobile": mobile,
        "Sec-CH-UA-Platform": f'"{platform}"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": user_agent,
    }


def build_identity():
    user_agent = random.choice(USER_AGENTS)
    viewport = random.choice(VIEWPORTS)
    locale = random.choice(LOCALES)
    timezone_id = random.choice(TIMEZONES)
    headers = build_browser_headers(user_agent, locale)
    return {
        "user_agent": user_agent,
        "viewport": viewport,
        "locale": locale,
        "timezone_id": timezone_id,
        "headers": headers,
    }


def analyze_obfuscation(script_text):
    markers = {
        "eval_usage": len(re.findall(r"\beval\s*\(", script_text)),
        "base64_blobs": len(re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", script_text)),
        "hex_encoding": len(re.findall(r"\\x[0-9a-fA-F]{2}", script_text)),
        "from_char_code": len(re.findall(r"String\.fromCharCode\s*\(", script_text)),
        "atob_calls": len(re.findall(r"\batob\s*\(", script_text)),
        "document_write": len(re.findall(r"document\.write\s*\(", script_text)),
    }
    score = min(
        100,
        markers["eval_usage"] * 12
        + markers["base64_blobs"] * 8
        + markers["hex_encoding"] * 1
        + markers["from_char_code"] * 10
        + markers["atob_calls"] * 8
        + markers["document_write"] * 6,
    )
    return score, markers


def detect_secrets(script_text):
    findings = []
    patterns = {
        "api_key": r"(?:api[_-]?key|api_secret|access_token|secret_key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "password_assignment": r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{1,}['\"]",
    }
    for name, pat in patterns.items():
        matches = re.findall(pat, script_text, flags=re.IGNORECASE)
        if matches:
            findings.append({"type": name, "count": len(matches)})
    return findings


def parse_hidden_inputs(soup):
    out = []
    sensitive_words = ["token", "csrf", "secret", "auth", "key", "password", "session"]
    for node in soup.select('input[type="hidden"]'):
        name = (node.get("name") or "").strip()
        value = (node.get("value") or "").strip()
        flag = any(w in name.lower() for w in sensitive_words)
        out.append({"name": name, "value": value, "sensitive_name": flag})
    return out


def parse_suspicious_variables(script_text):
    out = []
    pattern = re.compile(r"\b(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*([^;\n]+)", re.IGNORECASE)
    key_words = ["key", "token", "secret", "api", "endpoint", "url", "auth", "password"]
    for match in pattern.finditer(script_text):
        name = match.group(1).strip()
        raw_value = match.group(2).strip()
        low_name = name.lower()
        if not any(k in low_name for k in key_words):
            continue
        raw_low = raw_value.lower()
        suspicious = raw_low in {"null", "undefined", "''", '""'} or "todo" in raw_low or "changeme" in raw_low
        if suspicious:
            out.append({"name": name, "value": raw_value})
    return out


def extract_js_endpoints_from_text(script_text, base_url):
    patterns = [
        ("fetch", re.compile(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)),
        (
            "xhr_open",
            re.compile(r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        ),
        (
            "axios",
            re.compile(r"axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        ),
        (
            "jquery",
            re.compile(r"\$\s*\.\s*(?:ajax|get|post)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        ),
        ("path_literal", re.compile(r"['\"]((?:/|\.\.?/)[^'\"\s]{2,})['\"]", re.IGNORECASE)),
        ("template_literal", re.compile(r"`((?:/|\.\.?/)[^`\s]{2,})`", re.IGNORECASE)),
        (
            "var_assignment",
            re.compile(r"\b(?:var|let|const)\s+[a-zA-Z_$][\w$]*\s*=\s*['\"]((?:/|https?://)[^'\"]+)['\"]", re.IGNORECASE),
        ),
    ]
    found = []
    for pname, preg in patterns:
        for m in preg.finditer(script_text):
            raw = m.group(1).strip()
            absolute = normalize_url(raw, base_url)
            if not absolute:
                continue
            found.append(
                {
                    "url": absolute,
                    "raw_original": raw,
                    "pattern": pname,
                    "confidence": classify_confidence(pname),
                }
            )
    return found


def collect_attribute_urls(soup, base_url):
    out = []
    specs = [
        ("a", "href"),
        ("link", "href"),
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("source", "src"),
        ("video", "src"),
        ("audio", "src"),
        ("form", "action"),
    ]
    for tag, attr in specs:
        for node in soup.find_all(tag):
            raw = (node.get(attr) or "").strip()
            if not raw:
                continue
            absolute = normalize_url(raw, base_url)
            if not absolute:
                continue
            out.append(
                {
                    "url": absolute,
                    "discovery_method": f"{tag}.{attr}",
                    "raw_original": raw,
                }
            )
    for node in soup.find_all(style=True):
        inline_style = node.get("style") or ""
        for raw in re.findall(r"url\(([^)]+)\)", inline_style, flags=re.IGNORECASE):
            cleaned = raw.strip().strip('"').strip("'")
            absolute = normalize_url(cleaned, base_url)
            if absolute:
                out.append({"url": absolute, "discovery_method": "inline_style.url", "raw_original": cleaned})
    for node in soup.find_all("style"):
        css_text = node.get_text("\n", strip=False)
        for raw in re.findall(r"url\(([^)]+)\)", css_text, flags=re.IGNORECASE):
            cleaned = raw.strip().strip('"').strip("'")
            absolute = normalize_url(cleaned, base_url)
            if absolute:
                out.append({"url": absolute, "discovery_method": "style_tag.url", "raw_original": cleaned})
    return dedupe_dict_list(out, ["url", "discovery_method", "raw_original"])


def parse_form_parameters(soup, page_url):
    out = []
    sensitive_words = {"token", "csrf", "secret", "auth", "key", "password", "session", "jwt", "otp"}
    form_nodes = soup.find_all("form")
    for form in form_nodes:
        action = normalize_url((form.get("action") or "").strip(), page_url) or page_url
        method = (form.get("method") or "GET").upper()
        for node in form.find_all(["input", "textarea", "select"]):
            name = (node.get("name") or "").strip()
            if not name:
                continue
            value = (node.get("value") or "").strip()
            field_type = (node.get("type") or node.name or "text").lower()
            out.append(
                {
                    "name": name,
                    "sample_value": value,
                    "source": "form",
                    "source_url": action,
                    "http_method": method,
                    "field_type": field_type,
                    "sensitive_name": any(x in name.lower() for x in sensitive_words),
                    "confidence": "high" if field_type == "hidden" else "medium",
                }
            )
    return out


def parse_url_parameters(url_value, source):
    out = []
    parsed = urlparse(url_value)
    if not parsed.query:
        return out
    sensitive_words = {"token", "csrf", "secret", "auth", "key", "password", "session", "jwt", "otp"}
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not name:
            continue
        out.append(
            {
                "name": name,
                "sample_value": value,
                "source": source,
                "source_url": url_value,
                "http_method": "GET",
                "field_type": "query",
                "sensitive_name": any(x in name.lower() for x in sensitive_words),
                "confidence": "high",
            }
        )
    return out


def parse_js_parameters(script_text, source_url):
    out = []
    sensitive_words = {"token", "csrf", "secret", "auth", "key", "password", "session", "jwt", "otp"}
    key_matches = set(re.findall(r"['\"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['\"]\s*:", script_text))
    url_param_matches = set(re.findall(r"(?:append|set|get|has)\s*\(\s*['\"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['\"]", script_text))
    all_names = key_matches.union(url_param_matches)
    noisy = {"https", "http", "width", "height", "length", "status", "method", "headers", "body", "data", "url"}
    for name in all_names:
        lower = name.lower()
        if lower in noisy:
            continue
        if len(lower) < 3:
            continue
        confidence = "high" if any(x in lower for x in sensitive_words) else "low"
        out.append(
            {
                "name": name,
                "sample_value": "",
                "source": "javascript",
                "source_url": source_url,
                "http_method": "UNKNOWN",
                "field_type": "js_key",
                "sensitive_name": any(x in lower for x in sensitive_words),
                "confidence": confidence,
            }
        )
    return out


def parse_body_parameters(post_data, source_url, method):
    out = []
    if not post_data:
        return out
    sensitive_words = {"token", "csrf", "secret", "auth", "key", "password", "session", "jwt", "otp"}
    text = str(post_data).strip()
    if not text:
        return out
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_name = str(key).strip()
                if not key_name:
                    continue
                out.append(
                    {
                        "name": key_name,
                        "sample_value": str(value)[:180],
                        "source": "network_body",
                        "source_url": source_url,
                        "http_method": method,
                        "field_type": "json",
                        "sensitive_name": any(x in key_name.lower() for x in sensitive_words),
                        "confidence": "high",
                    }
                )
        return out
    except Exception:
        pass

    for key, value in parse_qsl(text, keep_blank_values=True):
        if not key:
            continue
        out.append(
            {
                "name": key,
                "sample_value": value,
                "source": "network_body",
                "source_url": source_url,
                "http_method": method,
                "field_type": "form_encoded",
                "sensitive_name": any(x in key.lower() for x in sensitive_words),
                "confidence": "high",
            }
        )
    return out


def build_hidden_parameters(final_url, all_collected_urls, all_requests_log, all_form_params, all_script_text):
    items = []
    items.extend(all_form_params)

    for c in all_collected_urls:
        u = c.get("url", "")
        if u:
            items.extend(parse_url_parameters(u, "collected_url"))

    for r in all_requests_log:
        req_url = normalize_url(r.get("url", ""), final_url)
        method = str(r.get("method", "GET") or "GET").upper()
        if req_url:
            items.extend(parse_url_parameters(req_url, "network_url"))
        items.extend(parse_body_parameters(r.get("post_data", ""), req_url or final_url, method))

    items.extend(parse_js_parameters(all_script_text, final_url))

    out = []
    seen = set()
    for i in items:
        name = (i.get("name") or "").strip()
        if not name:
            continue
        key = (name.lower(), i.get("source", ""), i.get("source_url", ""), i.get("field_type", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(i)

    out.sort(key=lambda x: (0 if x.get("sensitive_name") else 1, x.get("name", "").lower()))
    return out


def log_stage(stage):
    print(f"progress:{stage}", flush=True)


def build_redirect_chain(main_request):
    chain = []
    req = main_request
    while req is not None:
        chain.append(req.url)
        req = req.redirected_from
    return chain


def set_network_hooks(page):
    requests_log = []
    responses_log = []

    def on_request(req):
        headers = req.headers if isinstance(req.headers, dict) else {}
        requests_log.append(
            {
                "url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
                "request_headers": headers,
                "post_data": req.post_data or "",
            }
        )

    def on_response(res):
        req = res.request
        responses_log.append(
            {
                "url": res.url,
                "status": res.status,
                "resource_type": req.resource_type,
                "method": req.method,
                "response_headers": dict(res.headers),
            }
        )

    page.on("request", on_request)
    page.on("response", on_response)
    return requests_log, responses_log


async def crawl_internal_pages(context, seed_urls, base_host, max_pages=4):
    queue = []
    seen = set()
    for u in seed_urls:
        parsed = urlparse(u)
        if not parsed.netloc or parsed.netloc != base_host:
            continue
        if u in seen:
            continue
        seen.add(u)
        queue.append(u)

    visited = []
    all_requests = []
    all_responses = []
    all_collected = []
    all_js_found = []
    all_form_params = []
    all_script_text = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        page = await context.new_page()
        req_log, res_log = set_network_hooks(page)
        title = ""
        status = 0
        try:
            try:
                response = await page.goto(url, wait_until="networkidle", timeout=30000)
            except Exception:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(1.2)
            title = await page.title()
            status = response.status if response else 0
            html_content = await page.content()
            final_url = page.url
            hooked_calls = await page.evaluate("window.__intelliscan_calls || []")
            js_analysis = analyze_javascript(html_content, final_url, hooked_calls, res_log)
            soup = BeautifulSoup(html_content, "html.parser")
            collected_urls = collect_attribute_urls(soup, final_url)
            form_params = parse_form_parameters(soup, final_url)
            script_text = "\n".join(s.string or s.get_text("\n", strip=False) or "" for s in soup.find_all("script"))

            all_requests.extend(req_log)
            all_responses.extend(res_log)
            all_collected.extend(collected_urls)
            all_js_found.extend(js_analysis["js_discovered_urls"])
            all_form_params.extend(form_params)
            all_script_text.append(script_text)

            for node in soup.find_all("a"):
                href = normalize_url((node.get("href") or "").strip(), final_url)
                if not href:
                    continue
                p = urlparse(href)
                if p.netloc != base_host:
                    continue
                if href in seen:
                    continue
                seen.add(href)
                if len(queue) + len(visited) < max_pages * 3:
                    queue.append(href)
        except Exception:
            pass
        finally:
            visited.append({"url": url, "title": title, "status": status})
            await page.close()

    return {
        "visited_pages": visited,
        "requests_log": all_requests,
        "responses_log": all_responses,
        "collected_urls": all_collected,
        "js_discovered_urls": all_js_found,
        "form_parameters": all_form_params,
        "script_text": "\n".join(all_script_text),
    }


INIT_SCRIPT = r"""
(() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  window.__intelliscan_calls = [];
  const nativeFetch = window.fetch;
  window.fetch = function(...args) {
    try {
      window.__intelliscan_calls.push({ kind: 'fetch', url: String(args[0] || ''), ts: Date.now() });
    } catch (e) {}
    return nativeFetch.apply(this, args);
  };
  const nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      window.__intelliscan_calls.push({ kind: 'xhr', method: String(method || ''), url: String(url || ''), ts: Date.now() });
    } catch (e) {}
    return nativeOpen.call(this, method, url, ...rest);
  };
  const nativeEval = window.eval;
  window.eval = function(code) {
    try {
      const c = String(code || '');
      window.__intelliscan_calls.push({ kind: 'eval', snippet: c.slice(0, 240), ts: Date.now() });
    } catch (e) {}
    return nativeEval.call(this, code);
  };
})();
"""


def categorize_urls(base_url, network_responses, collected_urls, js_found):
    base_host = urlparse(base_url).netloc
    network_map = {}
    for n in network_responses:
        u = normalize_url(n.get("url", ""), base_url)
        if not u:
            continue
        network_map[u] = {
            "url": u,
            "resource_type": n.get("resource_type", "unknown"),
            "http_status": n.get("status", 0),
        }

    js_url_set = set(j.get("url", "") for j in js_found if j.get("url"))
    html_attr_set = set(c.get("url", "") for c in collected_urls if c.get("url"))
    network_set = set(network_map.keys())

    crawled = []
    for u, item in network_map.items():
        crawled.append(
            {
                "url": u,
                "resource_type": item["resource_type"],
                "http_status": item["http_status"],
                "also_discovered_in_javascript": u in js_url_set,
            }
        )

    collected = []
    for c in collected_urls:
        u = c.get("url", "")
        if not u:
            continue
        collected.append(
            {
                "url": u,
                "discovery_method": c.get("discovery_method", "unknown"),
                "raw_original_value": c.get("raw_original", ""),
                "appeared_in_network_log": u in network_set,
            }
        )

    hidden = []
    for j in js_found:
        u = j.get("url", "")
        if not u:
            continue
        if u in html_attr_set:
            continue
        hidden.append(
            {
                "url": u,
                "raw_original_value": j.get("raw_original", ""),
                "confidence": j.get("confidence", "low"),
                "called_during_session": u in network_set,
            }
        )

    crawled = dedupe_dict_list(crawled, ["url", "resource_type", "http_status", "also_discovered_in_javascript"])
    collected = dedupe_dict_list(collected, ["url", "discovery_method", "raw_original_value", "appeared_in_network_log"])
    hidden = dedupe_dict_list(hidden, ["url", "raw_original_value", "confidence", "called_during_session"])

    crawled_internal, crawled_third = domain_split(crawled, base_host)
    collected_internal, collected_third = domain_split(collected, base_host)
    hidden_internal, hidden_third = domain_split(hidden, base_host)

    return {
        "crawled_urls": crawled,
        "collected_urls": collected,
        "hidden_endpoints": hidden,
        "internal_paths": {
            "crawled": crawled_internal,
            "collected": collected_internal,
            "hidden": hidden_internal,
        },
        "third_party_domains": {
            "crawled": crawled_third,
            "collected": collected_third,
            "hidden": hidden_third,
        },
    }


def analyze_javascript(html_content, final_url, hooked_calls, network_responses):
    soup = BeautifulSoup(html_content, "html.parser")
    inline_scripts = []
    external_scripts = []
    all_script_text = []

    for s in soup.find_all("script"):
        src = (s.get("src") or "").strip()
        if src:
            norm = normalize_url(src, final_url)
            if norm:
                external_scripts.append({"url": norm, "raw_original": src})
        text = s.string or s.get_text("\n", strip=False) or ""
        if text.strip():
            inline_scripts.append(text)
            all_script_text.append(text)

    joined_script_text = "\n".join(all_script_text)
    obf_score, obf_markers = analyze_obfuscation(joined_script_text)
    hidden_inputs = parse_hidden_inputs(soup)
    suspicious_variables = parse_suspicious_variables(joined_script_text)
    secrets = detect_secrets(joined_script_text)

    js_found = []
    for block in inline_scripts:
        js_found.extend(extract_js_endpoints_from_text(block, final_url))

    for call in hooked_calls:
        raw = str(call.get("url", "")).strip()
        absolute = normalize_url(raw, final_url)
        if absolute:
            js_found.append(
                {
                    "url": absolute,
                    "raw_original": raw,
                    "pattern": f"hooked_{call.get('kind', 'unknown')}",
                    "confidence": "high",
                }
            )

    network_set = set(normalize_url(n.get("url", ""), final_url) for n in network_responses)
    js_found_clean = []
    for j in js_found:
        u = j.get("url", "")
        if not u:
            continue
        x = dict(j)
        x["called_during_session"] = u in network_set
        js_found_clean.append(x)

    js_found_clean = dedupe_dict_list(js_found_clean, ["url", "raw_original", "pattern", "confidence", "called_during_session"])
    external_scripts = dedupe_dict_list(external_scripts, ["url", "raw_original"])

    return {
        "inline_script_count": len(inline_scripts),
        "external_scripts": external_scripts,
        "obfuscation_score": obf_score,
        "obfuscation_markers": obf_markers,
        "hidden_inputs": hidden_inputs,
        "suspicious_variables": suspicious_variables,
        "secrets": secrets,
        "js_discovered_urls": js_found_clean,
    }


async def run_scan():
    if not TARGET_URL or not SCAN_ID:
        raise RuntimeError("Missing required environment values TARGET_URL or SCAN_ID")

    identity = build_identity()
    log_stage(PROGRESS_STAGES[0])

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=identity["user_agent"],
            viewport=identity["viewport"],
            locale=identity["locale"],
            timezone_id=identity["timezone_id"],
            extra_http_headers=identity["headers"],
        )
        await context.add_init_script(INIT_SCRIPT)
        log_stage(PROGRESS_STAGES[1])

        page = await context.new_page()
        requests_log, responses_log = set_network_hooks(page)

        try:
            main_response = await page.goto(TARGET_URL, wait_until="networkidle", timeout=45000)
        except Exception:
            main_response = await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=45000)
        await asyncio.sleep(3)
        log_stage(PROGRESS_STAGES[2])

        screenshot_bytes = await page.screenshot(full_page=True)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        log_stage(PROGRESS_STAGES[3])

        html_content = await page.content()
        final_url = page.url
        page_title = await page.title()
        cookies = await context.cookies()
        base_host = urlparse(final_url).netloc

        hooked_calls = await page.evaluate("window.__intelliscan_calls || []")
        js_analysis = analyze_javascript(html_content, final_url, hooked_calls, responses_log)
        log_stage(PROGRESS_STAGES[4])

        soup = BeautifulSoup(html_content, "html.parser")
        collected_urls = collect_attribute_urls(soup, final_url)
        initial_form_parameters = parse_form_parameters(soup, final_url)

        internal_seed_links = [
            x.get("url", "")
            for x in collected_urls
            if x.get("discovery_method") == "a.href" and urlparse(x.get("url", "")).netloc == base_host
        ]
        crawl_data = await crawl_internal_pages(context, internal_seed_links, base_host, max_pages=5)

        merged_requests_log = requests_log + crawl_data["requests_log"]
        merged_responses_log = responses_log + crawl_data["responses_log"]
        merged_collected_urls = dedupe_dict_list(collected_urls + crawl_data["collected_urls"], ["url", "discovery_method", "raw_original"])
        merged_js_urls = dedupe_dict_list(js_analysis["js_discovered_urls"] + crawl_data["js_discovered_urls"], ["url", "raw_original", "pattern", "confidence", "called_during_session"])
        merged_form_parameters = dedupe_dict_list(initial_form_parameters + crawl_data["form_parameters"], ["name", "source", "source_url", "field_type", "http_method"])
        merged_script_text = "\n".join([s.string or s.get_text("\n", strip=False) or "" for s in soup.find_all("script")]) + "\n" + crawl_data["script_text"]

        categorized = categorize_urls(final_url, merged_responses_log, merged_collected_urls, merged_js_urls)
        hidden_parameters = build_hidden_parameters(final_url, merged_collected_urls, merged_requests_log, merged_form_parameters, merged_script_text)
        log_stage(PROGRESS_STAGES[5])

        network_activity = dedupe_dict_list(
            [
                {
                    "url": normalize_url(r.get("url", ""), final_url),
                    "method": r.get("method", "GET"),
                    "resource_type": r.get("resource_type", "unknown"),
                    "request_headers": r.get("request_headers", {}),
                    "status": next((x.get("status", 0) for x in merged_responses_log if x.get("url") == r.get("url")), 0),
                    "response_headers": next((x.get("response_headers", {}) for x in merged_responses_log if x.get("url") == r.get("url")), {}),
                }
                for r in merged_requests_log
                if normalize_url(r.get("url", ""), final_url)
            ],
            ["url", "method", "resource_type", "status"],
        )
        log_stage(PROGRESS_STAGES[6])

        redirect_chain = []
        if main_response is not None:
            redirect_chain = build_redirect_chain(main_response.request)

        result = {
            "scan_id": SCAN_ID,
            "target_url": TARGET_URL,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "page_title": page_title,
            "cookies": [{"name": c.get("name", ""), "value": c.get("value", "")} for c in cookies],
            "identity": identity,
            "network_activity": network_activity,
            "crawl_summary": {
                "visited_pages": crawl_data["visited_pages"],
                "visited_count": len(crawl_data["visited_pages"]),
            },
            "crawled_urls": categorized["crawled_urls"],
            "collected_urls": categorized["collected_urls"],
            "hidden_endpoints": categorized["hidden_endpoints"],
            "hidden_parameters": hidden_parameters,
            "internal_paths": categorized["internal_paths"],
            "third_party_domains": categorized["third_party_domains"],
            "js_analysis": {
                "inline_script_count": js_analysis["inline_script_count"],
                "external_scripts": js_analysis["external_scripts"],
                "obfuscation_score": js_analysis["obfuscation_score"],
                "obfuscation_markers": js_analysis["obfuscation_markers"],
                "hidden_inputs": js_analysis["hidden_inputs"],
                "suspicious_variables": js_analysis["suspicious_variables"],
                "secrets": js_analysis["secrets"],
                "js_discovered_urls": js_analysis["js_discovered_urls"],
            },
            "screenshot_base64": screenshot_b64,
        }

        await browser.close()
        return result


async def main():
    try:
        print("scanner:start", flush=True)
        result = await run_scan()
        output_path = f"scan-result-{SCAN_ID}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        print(f"scanner:artifact:{output_path}", flush=True)
        print("scanner:complete", flush=True)
    except Exception as exc:
        print(f"scanner:error:{exc}", flush=True)
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        sys.exit(1)
