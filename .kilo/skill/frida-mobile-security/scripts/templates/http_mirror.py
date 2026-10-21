#!/usr/bin/env python3
"""HTTP 镜像转发器（通用，与具体 App / hook 点解耦）

把 Frida JS 采集到的明文包装成 HTTP 请求，转发给代理工具（Yakit / mitmproxy / Burp），
在代理 History 里直接看请求与响应。内置 echo 服务消除代理 502。

──────────────────────────── JS 侧契约 ────────────────────────────
    send({
      kind: "mirror",
      method: "POST" | "PUT",      # 可省略：按路径自动推断（含 /resp → 响应方法）
      path: "/sock/req/60",
      headers: {"X-Action": "60"},
      body: "{\"grid\":\"600621\"}"   # 或 body_b64: "<base64>"
    });
    send({kind: "log", message: "..."})   # 透传 JS 日志

──────────────────────────── 请求方法约定 ────────────────────────────
默认 TZTREQ=请求 / TZTRESP=响应（Method 列一眼可分方向，人眼最直观）。
代理不支持自定义方法时（部分 Burp 版本），用 --req-method POST --resp-method PUT 回退。
JS 未提供 method 时：--auto-method（默认开）按 path 是否含 "/resp" 判定。
自定义方法在 Yakit 里同样能透传，Method 列一眼可分方向。

──────────────────────────── 重放设计 ────────────────────────────
本模块提供三层重放，按需要选：

  1) 原样重发（不依赖 App）
       GET  /__history?limit=20            取最近捕获的包
       POST /__replay {"index":0}          原样重发
       POST /__replay {"index":0,"body":"..."}   改包后重发
     适用于：改字段、重复发包、对比响应。包体经代理转发，Yakit 里会新增一条记录。

  2) 调 JS 侧 RPC（App 内真实重放）
       POST /__rpc/<method> [args...]
     适用于 hook 脚本里 exports 暴露的 send(action, params) / resps(action) 等，
     走 App 自己的协议栈（加密、会话、socket），返回 App 的真实响应。

  3) 代理工具自带 Repeater
     把镜像请求发送到 Repeater，改 body 后发到 /__replay 或 /__rpc/<method>。

──────────────────────────── 方向判定 ────────────────────────────
不同 App 的路径命名不统一，因此按优先级判定"请求/响应"，并记录来源：

  1. JS 显式给 dir: "req" | "resp"（最可靠，与路径无关）
  2. JS 给 method：等于 --req-method / --resp-method 时直接映射
  3. 路径匹配 --resp-patterns / --req-patterns（默认已含 resp/response/req/request 等）
  4. 都不匹配 → --default-dir（默认 req）

日志里的 [dir/source] 会标明来源：field / method / path / default。
换 App 只需加/改 pattern，不用改代码：
  --resp-patterns "/resp,resp,response,downlink,down"
  --req-patterns  "/req,req,request,uplink,up"

──────────────────────────── 运行前准备 ────────────────────────────
  1. 代理工具监听 --proxy（默认 127.0.0.1:8085），并允许回源到 --echo（默认 8086）
  2. 设备侧 Gadget 已注入，adb forward tcp:27042 tcp:27042
  3. Frida JS 已实现 send({kind:"mirror", ...})
  4. 先跑 --check 自检：代理连通性、脚本存在性、echo 端口占用

──────────────────────────── 用法 ────────────────────────────
  直连（推荐）：
    python3 http_mirror.py --script hooks.js --device 127.0.0.1:27042
    python3 http_mirror.py --script hooks.js --spawn com.example.app
  只做自检：
    python3 http_mirror.py --script hooks.js --check
  tail frida CLI 日志（JS 用 console.log("###MIRROR###"+JSON.stringify(rec))）：
    python3 http_mirror.py --tail cli.log

    控制面（echo 端口）：
      GET  /__stats            计数器与运行状态
      GET  /__exports          列出 JS 侧 rpc.exports
      GET  /__history?limit=N  最近捕获的包（最多 --history-size）
      POST /__replay           重放：{"index":N,"method":"POST","path":"/x","body":"..."}
      POST /__rpc/<method>     body 为 JSON 数组（位置参数）或对象（关键字参数）

──────────────────────────── 关键设计（踩坑结论，勿改） ────────────────────────────
  - 代理是"代理"：收到请求必须转发到可达目标；echo 把请求体原样回显，
    于是 History 里 请求=响应=业务明文，且不会 502。
  - 必须保持主线程存活（sleep 循环）；后台读 sys.stdin 会立即 EOF，session 秒退。
  - JS 侧只 send()，不创建 Java 对象（QuickJS 下非主线程 JNI attach 会 SIGABRT）。
"""
import argparse
import base64
import json
import os
import queue
import socket
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARK = "###MIRROR###"
SCRIPT = None            # frida Script，供 /__rpc 使用
SCRIPT_LOCK = threading.Lock()
HISTORY = deque(maxlen=200)
HISTORY_LOCK = threading.Lock()
METHODS = {"req": "POST", "resp": "PUT"}
AUTO_METHOD = [True]
ALLOWED = ("POST", "PUT", "PATCH", "GET", "DELETE", "TZTREQ", "TZTRESP")
RESP_PATTERNS = ["/resp", "resp", "response", "downlink", "down"]
REQ_PATTERNS = ["/req", "req", "request", "uplink", "up"]
DEFAULT_DIR = ["req"]


class Stats(object):
    def __init__(self):
        self._lock = threading.Lock()
        self.data = {
            "recv": 0, "sent": 0, "err": 0, "drop": 0, "replay": 0, "rpc": 0,
            "start": time.time(), "last": None,
        }

    def inc(self, key, n=1):
        with self._lock:
            self.data[key] = self.data.get(key, 0) + n
            self.data["last"] = time.time()

    def snapshot(self):
        with self._lock:
            out = dict(self.data)
        out["uptime"] = int(time.time() - out["start"])
        return out


STATS = Stats()
OUT_LOCK = threading.Lock()
LOG_FILE = [None]


def log(msg, level="INFO"):
    line = "[%s] %-5s %s" % (time.strftime("%H:%M:%S"), level, msg)
    with OUT_LOCK:
        print(line, flush=True)
        if LOG_FILE[0]:
            try:
                with open(LOG_FILE[0], "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass


def split_hostport(s, default_port):
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, default_port


def compile_filter(pattern):
    """空 = 不过滤；re:xxx = 正则；其余 = 子串（不区分大小写）"""
    if not pattern:
        return None
    if pattern.startswith("re:"):
        import re
        rx = re.compile(pattern[3:])
        return lambda s: bool(rx.search(s))
    low = pattern.lower()
    return lambda s: low in s.lower()


def path_allowed(path, include, exclude):
    if include is not None and not include(path):
        return False
    if exclude is not None and exclude(path):
        return False
    return True


def classify(rec):
    """返回 (dir, source)：dir 为 req/resp，source 为 field/method/path/default"""
    explicit = str(rec.get("dir") or rec.get("direction") or "").lower()
    if explicit in ("req", "request", "resp", "response"):
        return ("resp" if explicit.startswith("resp") else "req"), "field"

    m = str(rec.get("method") or "").upper()
    if m:
        if m == METHODS["resp"]:
            return "resp", "method"
        if m == METHODS["req"]:
            return "req", "method"

    if AUTO_METHOD[0]:
        path = str(rec.get("path") or "").lower()
        for pat in RESP_PATTERNS:
            if pat and pat.lower() in path:
                return "resp", "path"
        for pat in REQ_PATTERNS:
            if pat and pat.lower() in path:
                return "req", "path"

    return DEFAULT_DIR[0], "default"


def pick_method(rec):
    """显式 method 优先；否则按方向取 --req-method / --resp-method"""
    m = str(rec.get("method") or "").upper()
    if m in ALLOWED:
        return m
    d, _ = classify(rec)
    return METHODS["resp"] if d == "resp" else METHODS["req"]


def body_of(rec, limit):
    if isinstance(rec.get("body_b64"), str):
        try:
            raw = base64.b64decode(rec["body_b64"])
            text = raw.decode("utf-8", "replace")
        except Exception:
            text = ""
    else:
        text = rec.get("body", "")
        if not isinstance(text, str):
            text = json.dumps(text, ensure_ascii=False)
    if limit and len(text) > limit:
        return text[:limit] + "\n... <%d bytes omitted>" % (len(text) - limit)
    return text


# ---------------- echo + 控制面 ----------------

class EchoHandler(BaseHTTPRequestHandler):
    """把请求体原样回显；同时提供 /__stats、/__history、/__replay、/__rpc、/__exports"""

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(n) if n > 0 else b""
        except Exception:
            return b""

    def _send(self, payload, code=200):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=False), code)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/__stats":
            self._json(STATS.snapshot())
            return
        if path == "/__exports":
            self._json(self._exports())
            return
        if path == "/__history":
            self._history(query)
            return
        self._send(self._read_body() or b"{}")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/__rpc/"):
            self._rpc(path[len("/__rpc/"):], self._read_body())
            return
        if path == "/__replay":
            self._replay(self._read_body())
            return
        self._send(self._read_body() or b"{}")

    def do_PUT(self):
        self._send(self._read_body() or b"{}")

    do_PATCH = do_PUT
    do_TZTREQ = do_PUT
    do_TZTRESP = do_PUT

    def __getattr__(self, name):
        # 任意自定义方法都当回显处理，避免代理回源 501
        if name.startswith("do_"):
            return self._echo_any
        raise AttributeError(name)

    def _echo_any(self):
        self._send(self._read_body() or b"{}")

    @staticmethod
    def _exports():
        if SCRIPT is None:
            return {"err": "script not loaded"}
        try:
            return {"exports": list(SCRIPT.list_exports_sync())}
        except Exception as e:
            return {"err": str(e)}

    def _history(self, query):
        limit = 20
        for kv in query.split("&"):
            if kv.startswith("limit="):
                try:
                    limit = max(1, int(kv[6:]))
                except ValueError:
                    pass
        with HISTORY_LOCK:
            items = list(HISTORY)[-limit:]
        out = []
        for i, rec in enumerate(items):
            out.append({
                "index": len(HISTORY) - len(items) + i,
                "method": rec.get("method"),
                "path": rec.get("path"),
                "dir": rec.get("dir"),
                "dir_source": rec.get("dir_source"),
                "len": len(str(rec.get("body", ""))),
            })
        self._json({"count": len(out), "items": out})

    def _replay(self, raw):
        if FWD[0] is None:
            self._json({"ok": False, "err": "forwarder not ready"}, 503)
            return
        try:
            req = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except Exception as e:
            self._json({"ok": False, "err": "bad json: %s" % e}, 400)
            return
        index = req.get("index", -1)
        with HISTORY_LOCK:
            total = len(HISTORY)
            if not isinstance(index, int) or index < 0 or index >= total:
                self._json({"ok": False, "err": "index out of range 0..%d" % (total - 1)}, 400)
                return
            rec = dict(HISTORY[index])
        for k in ("method", "path", "headers", "body", "body_b64"):
            if k in req:
                rec[k] = req[k]
        handle_record(FWD[0], rec, None, None, MAX_BODY[0], source="replay")
        self._json({"ok": True, "replayed": index, "method": rec.get("method"), "path": rec.get("path")})

    def _rpc(self, method, raw):
        if SCRIPT is None:
            self._json({"ok": False, "err": "script not loaded"}, 503)
            return
        try:
            arg = json.loads(raw.decode("utf-8")) if raw.strip() else []
        except Exception as e:
            self._json({"ok": False, "err": "bad json: %s" % e}, 400)
            return
        try:
            fn = getattr(SCRIPT.exports_sync, method)
            if isinstance(arg, dict):
                result = fn(**arg)
            elif isinstance(arg, list):
                result = fn(*arg)
            else:
                result = fn(arg)
            STATS.inc("rpc")
            self._json({"ok": True, "result": result})
        except Exception as e:
            self._json({"ok": False, "err": str(e)}, 500)

    def log_message(self, *a):
        pass


def start_echo(port):
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), EchoHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        log("echo/control ready on 127.0.0.1:%d" % port)
        return srv
    except Exception as e:
        log("echo server FAILED: %s" % e, "ERROR")
        return None


# ---------------- 转发 ----------------

def show_packet(method, target_host, path, headers, body, n, quiet, meta=""):
    if quiet:
        log("FWD  %-8s %-32s [%s] len=%d total=%d" % (method, path, meta, len(body), n))
        return
    print("\n" + "=" * 78)
    print("[%s] #%d  %s http://%s%s" % (time.strftime("%H:%M:%S"), n, method, target_host, path))
    for k, v in (headers or {}).items():
        print("    %s: %s" % (k, v))
    print("    [%s]" % meta)
    print("    Content-Length: %d" % len(body.encode("utf-8")))
    print("-" * 78)
    print(body)
    print("=" * 78, flush=True)


def forward(proxy, target_host, method, path, headers, body, quiet, timeout, meta=""):
    try:
        s = socket.create_connection(proxy, timeout=timeout)
        b = body.encode("utf-8")
        head = ("%s http://%s%s HTTP/1.1\r\nHost: %s\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                "Content-Length: %d\r\nConnection: close\r\n"
                % (method, target_host, path, target_host, len(b)))
        for k, v in (headers or {}).items():
            if k.lower() in ("content-length", "host", "connection"):
                continue
            head += "%s: %s\r\n" % (k, v)
        s.sendall((head + "\r\n").encode("utf-8") + b)
        s.close()
        STATS.inc("sent")
        show_packet(method, target_host, path, headers, body, STATS.data["sent"], quiet, meta)
    except Exception as e:
        STATS.inc("err")
        log("FWD-ERR %s %s : %s" % (method, path, e), "ERROR")


class Forwarder(object):
    """有界队列 + 固定 worker，避免每个包一个线程"""

    def __init__(self, proxy, target_host, quiet, timeout=2.0, workers=4, maxsize=2000):
        self.q = queue.Queue(maxsize=maxsize)
        self.proxy = proxy
        self.target_host = target_host
        self.quiet = quiet
        self.timeout = timeout
        for i in range(workers):
            t = threading.Thread(target=self._worker, name="fwd-%d" % i, daemon=True)
            t.start()

    def submit(self, method, path, headers, body, meta=""):
        try:
            self.q.put_nowait((method, path, headers, body, meta))
        except queue.Full:
            STATS.inc("drop")

    def _worker(self):
        while True:
            method, path, headers, body, meta = self.q.get()
            forward(self.proxy, self.target_host, method, path, headers, body,
                    self.quiet, self.timeout, meta)


# ---------------- 记录处理 ----------------

FWD = [None]
INCLUDE = [None]
EXCLUDE = [None]
MAX_BODY = [0]


def handle_record(fwd, rec, include, exclude, max_body, source="live"):
    d, how = classify(rec)
    method = pick_method(rec)

    enriched = dict(rec)
    enriched["method"] = method
    enriched["dir"] = d
    enriched["dir_source"] = how

    if source == "live":
        STATS.inc("recv")
        with HISTORY_LOCK:
            HISTORY.append(enriched)
    else:
        STATS.inc("replay")

    path = str(enriched.get("path") or "/")
    if not path_allowed(path, include, exclude):
        return
    fwd.submit(method, path, enriched.get("headers") or {}, body_of(enriched, max_body),
               "%s/%s" % (d, how))


# ---------------- 自检 ----------------

def preflight(args, proxy):
    ok = True
    try:
        s = socket.create_connection(proxy, timeout=1.5)
        s.close()
        log("preflight: proxy %s:%d 可达" % proxy)
    except Exception as e:
        log("preflight: proxy %s:%d 不可达（%s）" % (proxy[0], proxy[1], e), "ERROR")
        ok = False

    if args.script:
        if os.path.exists(args.script):
            log("preflight: script 存在 %s" % args.script)
        else:
            log("preflight: script 不存在 %s" % args.script, "ERROR")
            ok = False

    if not args.no_echo:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", args.echo))
            log("preflight: echo 端口 %d 可用" % args.echo)
        except Exception as e:
            log("preflight: echo 端口 %d 被占用（%s）" % (args.echo, e), "ERROR")
            ok = False
        finally:
            probe.close()
    return ok


def print_ready(args, proxy):
    print("")
    print("=" * 70)
    print(" READY")
    print("   mirror  : JS send({kind:'mirror', method, path, headers, body})")
    print("   proxy   : %s:%d" % proxy)
    print("   echo    : 127.0.0.1:%d (control plane)" % args.echo)
    print("   methods : req=%s resp=%s auto=%s default=%s"
          % (METHODS["req"], METHODS["resp"], "on" if AUTO_METHOD[0] else "off", DEFAULT_DIR[0]))
    print("   dir     : field > method > path(%s | %s)"
          % (",".join(RESP_PATTERNS), ",".join(REQ_PATTERNS)))
    print("   control : GET /__stats | GET /__exports | GET /__history?limit=20")
    print("   replay  : POST /__replay {\"index\":0,\"body\":\"...\"}")
    print("   rpc     : POST /__rpc/<method> [args...]")
    print("   note    : 代理不支持自定义方法时加 --req-method POST --resp-method PUT")
    print("=" * 70)
    print("", flush=True)


# ---------------- 运行模式 ----------------

def run_tail(args, fwd, include, exclude):
    logfile = args.tail
    log("tailing %s -> %s:%d" % (logfile, fwd.proxy[0], fwd.proxy[1]))
    pos = 0
    while True:
        try:
            if not os.path.exists(logfile):
                time.sleep(0.5)
                continue
            with open(logfile, "rb") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except Exception:
            time.sleep(0.5)
            continue
        if not chunk:
            time.sleep(0.3)
            continue
        for line in chunk.decode("utf-8", "replace").splitlines():
            i = line.find(MARK)
            if i < 0:
                continue
            try:
                handle_record(fwd, json.loads(line[i + len(MARK):]), include, exclude, args.max_body)
            except Exception as e:
                log("PARSE-ERR %s" % e, "ERROR")


def connect(args):
    import frida
    dev = frida.get_device_manager().add_remote_device(args.device)
    if args.spawn:
        pid = dev.spawn([args.spawn])
        log("spawned %s pid=%d" % (args.spawn, pid))
        session = dev.attach(pid)
        dev.resume(pid)
        return dev, session, pid
    if args.pid:
        return dev, dev.attach(int(args.pid)), int(args.pid)
    return dev, dev.attach(args.target), args.target


def load_script(session, args):
    with open(args.script, encoding="utf-8") as f:
        js = f.read()
    if args.config:
        js = "var CONFIG_OVERRIDE = %s;\n" % args.config + js
    script = session.create_script(js)

    def on_message(msg, data):
        if msg.get("type") == "error":
            log("JS-ERROR %s" % str(msg.get("description"))[:500], "ERROR")
            return
        if msg.get("type") != "send":
            return
        p = msg.get("payload")
        if not isinstance(p, dict):
            return
        if p.get("kind") == "log":
            log("JS %s" % p.get("message", ""))
        elif p.get("kind") == "mirror":
            handle_record(FWD[0], p, INCLUDE[0], EXCLUDE[0], MAX_BODY[0])

    script.on("message", on_message)
    script.load()
    return script


def run_script(args):
    global SCRIPT
    log("=== stage 1: connect %s ===" % args.device)
    dev, session, target = connect(args)
    log("attached: %s" % target)
    try:
        log("device: %s" % dev)
    except Exception:
        pass

    log("=== stage 2: load %s ===" % args.script)
    with SCRIPT_LOCK:
        SCRIPT = load_script(session, args)
    log("script loaded")

    log("=== stage 3: running (Ctrl+C 退出) ===")
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        with SCRIPT_LOCK:
            SCRIPT = None
        try:
            session.detach()
        except Exception:
            pass
        log("detach: %s" % json.dumps(STATS.snapshot(), ensure_ascii=False))


def main():
    global HISTORY, ALLOWED
    ap = argparse.ArgumentParser(description="HTTP 镜像转发器（Frida → 代理）")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--script", help="Frida JS 文件（直连模式）")
    src.add_argument("--tail", help="frida CLI 日志（tail 模式）")

    ap.add_argument("--device", default="127.0.0.1:27042", help="gadget 地址")
    ap.add_argument("--target", default="Gadget", help="attach 目标名（默认 Gadget）")
    ap.add_argument("--spawn", default="", help="spawn 的应用包名（frida-server）")
    ap.add_argument("--pid", type=int, default=0, help="attach 指定 pid")
    ap.add_argument("--config", default="", help="注入 CONFIG_OVERRIDE 的 JSON")

    ap.add_argument("--proxy", default="127.0.0.1:8085", help="代理/抓包工具端口")
    ap.add_argument("--echo", type=int, default=8086, help="echo/控制面端口")
    ap.add_argument("--no-echo", action="store_true")

    ap.add_argument("--req-method", default="TZTREQ", help="请求方向使用的 HTTP 方法（默认 TZTREQ）")
    ap.add_argument("--resp-method", default="TZTRESP", help="响应方向使用的 HTTP 方法（默认 TZTRESP）")
    ap.add_argument("--no-auto-method", action="store_true", help="关闭按路径自动推断方向")
    ap.add_argument("--resp-patterns", default="", help="响应路径模式，逗号分隔（默认 /resp,resp,response,downlink,down）")
    ap.add_argument("--req-patterns", default="", help="请求路径模式，逗号分隔（默认 /req,req,request,uplink,up）")
    ap.add_argument("--default-dir", default="req", choices=["req", "resp"], help="无法判定时的默认方向")
    ap.add_argument("--include", default="", help="只看匹配路径（子串，或 re:正则）")
    ap.add_argument("--exclude", default="", help="排除匹配路径（子串，或 re:正则）")
    ap.add_argument("--max-body", type=int, default=0, help="转发体截断上限，0=不限")
    ap.add_argument("--history-size", type=int, default=200, help="重放历史保留条数")
    ap.add_argument("--timeout", type=float, default=2.0, help="代理连接超时")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--quiet", action="store_true", help="只打一行摘要")
    ap.add_argument("--log-file", default="", help="同时写日志文件")
    ap.add_argument("--check", action="store_true", help="只做启动自检后退出（可省略 --script/--tail）")
    ap.add_argument("--version", action="version", version="http_mirror 2.0")
    args = ap.parse_args()
    if not args.script and not args.tail and not args.check:
        ap.error("需要 --script 或 --tail（--check 可省略）")

    LOG_FILE[0] = args.log_file or None
    proxy = split_hostport(args.proxy, 8085)
    target_host = "127.0.0.1:%d" % args.echo

    METHODS["req"] = args.req_method.upper()
    METHODS["resp"] = args.resp_method.upper()
    ALLOWED = tuple(sorted(set(ALLOWED) | {METHODS["req"], METHODS["resp"]}))
    AUTO_METHOD[0] = not args.no_auto_method
    if args.resp_patterns:
        RESP_PATTERNS[:] = [x.strip() for x in args.resp_patterns.split(",") if x.strip()]
    if args.req_patterns:
        REQ_PATTERNS[:] = [x.strip() for x in args.req_patterns.split(",") if x.strip()]
    DEFAULT_DIR[0] = args.default_dir
    MAX_BODY[0] = args.max_body
    HISTORY = deque(maxlen=max(1, args.history_size))

    ok = preflight(args, proxy)
    if args.check:
        print_ready(args, proxy)
        sys.exit(0 if ok else 1)
    if not ok:
        log("自检未通过，仍继续启动（Ctrl+C 退出）", "WARN")

    FWD[0] = Forwarder(proxy, target_host, args.quiet, args.timeout, args.workers)
    INCLUDE[0] = compile_filter(args.include)
    EXCLUDE[0] = compile_filter(args.exclude)

    if not args.no_echo:
        start_echo(args.echo)
    print_ready(args, proxy)

    if args.tail:
        run_tail(args, FWD[0], INCLUDE[0], EXCLUDE[0])
    else:
        run_script(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
