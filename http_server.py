#!/usr/bin/env python3
"""Публичная проверка: отвечает ли площадка и что это за домен.

verity_gate.py различает три вещи, которые обычно смешивают:
домен существует и отвечает; домен есть, но это корень компании, а площадка
живёт по пути; домен не отвечает вовсе.

Наружу выставлено ровно это. Важное ограничение сохраняется и здесь:
`PASSED_TECHNICAL` — не `VERIFIED`. Техническая проверка не говорит о
комиссиях, правилах и добросовестности площадки. Обёртка не имеет права
превращать первый вывод во второй.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verity_gate as vg  # noqa: E402

LANDING = """<!doctype html><meta charset=utf-8><title>verity — platform due diligence</title>
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.6 system-ui,sans-serif;
      max-width:760px;margin:60px auto;padding:0 24px}
 code{background:#141821;padding:2px 6px;border-radius:5px;color:#f0a35e}
 pre{background:#141821;padding:12px;border-radius:9px;overflow:auto;font-size:14px}
 h1{font-size:26px;margin-bottom:4px} .s{color:#969eac}
 .box{background:#141821;border-radius:10px;padding:14px 18px;margin:14px 0}
 .warn{border-left:3px solid #f0a35e}
</style>
<h1>verity</h1>
<p class=s>Is that platform real? Three answers, not two.</p>

<div class=box><b>The distinction.</b> A domain that answers is not the same as a
platform you can use. The domain may be the corporate root, with the actual
marketplace buried at a path nobody linked to. Collapsing those into
"works / doesn't" is how dead listings get treated as live ones.</div>

<div class=box warn><b>What a pass does not mean.</b> <code>PASSED_TECHNICAL</code>
is not <code>VERIFIED</code>. It says the site responds. Fees, terms and whether
the operator is honest are untouched by an HTTP request, and a green result
here must never be reported as an endorsement.</div>

<h2>Try it</h2>
<pre>curl 'http://HOST:PORT/check?url=https://example.com'</pre>

<p class=s>Verdicts: <code>PASSED_TECHNICAL</code> &middot;
<code>NEEDS_PATH</code> &middot; <code>DEAD</code></p>
"""


def _base_url() -> str:
    """Публичный адрес: в sitemap обязаны быть абсолютные URL."""
    import os
    return os.environ.get("VERITY_BASE_URL", "https://rta.lat/verity").rstrip("/")


def _robots() -> str:
    """Краулеров пускаем: индексация витрины — это трафик."""
    return ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /mcp\n"
            f"Sitemap: {_base_url()}/sitemap.xml\n")


def _sitemap() -> str:
    """Карта сайта: документы, а не endpoints.

    `/subscribe`, `/quote`, `/check` сюда не идут — их индексация
    бессмысленна, это машиночитаемые адреса.
    """
    base = _base_url()
    urls = "".join(
        f"<url><loc>{base}{page}</loc></url>"
        for page in ('/', '/health')
    )
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{urls}</urlset>")


class Handler(BaseHTTPRequestHandler):
    server_version = "verity"

    def _send(self, code: int, payload: dict | str) -> None:
        raw = payload.encode() if isinstance(payload, str) else json.dumps(
            payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type",
                         "text/html; charset=utf-8" if isinstance(payload, str)
                         else "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        if path.startswith("/verity"):
            path = path[len("/verity"):] or "/"
        if path == "/robots.txt":
            self._send(200, _robots())
        elif path == "/sitemap.xml":
            self._send(200, _sitemap())
        if path == "/":
            return self._send(200, LANDING)
        if path == "/health":
            return self._send(200, {"status": "ok", "service": "verity"})
        if path != "/check":
            return self._send(404, {"error": "not found", "path": path})
        url = (q.get("url") or [""])[0].strip()
        if not url:
            return self._send(400, {"error": "supply ?url=..."})
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            status, final, title, error, size, extra = vg.probe_host(url)
        except Exception as exc:  # noqa: BLE001
            return self._send(200, {"url": url, "verdict": vg.Verdict.DEAD,
                                    "error": f"{type(exc).__name__}: {exc}"})
        if status is None:
            verdict = vg.Verdict.DEAD
        elif vg.is_parked(final or "", title or "", size):
            verdict = vg.Verdict.DEAD
        else:
            host = urlparse(final or url).hostname or ""
            verdict = (vg.Verdict.NEEDS_PATH
                       if vg.domain_kind([host]) == "corporate_root"
                       else vg.Verdict.PASSED_TECHNICAL)
        self._send(200, {
            "url": url,
            "verdict": verdict,
            "status": status,
            "final_url": final,
            "title": title,
            "bytes": size,
            "error": error,
            "detected": extra,
            "note": ("PASSED_TECHNICAL is not VERIFIED: fees, terms and the "
                     "operator's conduct remain unverified."),
        })

    def log_message(self, *_a) -> None:
        pass


def serve(host: str = "127.0.0.1", port: int = 8188) -> None:
    print(f"verity: http://{host}:{port}", flush=True)
    srv = ThreadingHTTPServer((host, port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8188)
    a = ap.parse_args()
    serve(a.host, a.port)