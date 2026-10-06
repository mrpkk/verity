"""VERITY-GATE: проверка каналов дистрибуции перед любым использованием.

Зачем этот инструмент
----------------------
Канон (`roadmapV4.md`, Часть IX) перечисляет около 70 площадок, но помечает
все, кроме Moltbook, как `UNVERIFIED`. Правило XIX.C4 жёсткое: **площадка без
пройденного VERITY-GATE каналом не считается**. То есть счёт
`CHANNELS_BEFORE_MVP` сегодня равен нулю, и любое упоминание этих имён в
маркетинге — нарушение канона.

Инструмент делает то, что не сделали пять иссл��дователей: проверяет площадки
вживую, а не пересказывает про них. Только read-only запросы (DNS + GET) —
никаких регистраций, листингов и публикаций.

Что проверяется
---------------
1. **Существует ли.** DNS-резолв. Нет A/AAAA-записи — домен не существует.
2. **Жив ли сайт.** HTTPS GET с редиректами, код ответа, финальный URL.
3. **Не фрод ли.** Косвенные сигналы: подозрительно молодой домен в теле
   ответа, отсутствие контактов в `<title>`/meta, redirect на сторонний домен.

Чего инструмент НЕ делает
--------------------------
Не судит о качестве площадки, не проверяет условия монетизации и не читает
пользовательские соглашения. Всё это — ручная работа человека после
технической проверки. Поэтому вердикт здесь один: `PASSED_TECHNICAL`, и он
**не равен** `VERIFIED` в смысле канона. Финальное решение — за владельцем.

Этическая оговорка
------------------
Инструмент не обходит защиту, не имитирует браузер и не подделавает
идентичность. Один GET на страницу площадки — это то же, что делает человек,
открывший ссылку. Массовость (70 доменов) не меняет сути: это проверка
доступности чужих сайтов, а не сбор персональных данных.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import subprocess
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "Platform",
    "ProbeResult",
    "Verdict",
    "extract_platforms",
    "probe_host",
    "run_gate",
    "count_channels",
    "DEFAULT_CANON",
    "DEFAULT_DOMAINS",
    "DEFAULT_OUT",
]

DEFAULT_CANON = Path(
    "/home/iamthat/Документы/work/projectBooks/tmpSPEC/roadmapV4.md"
)
DEFAULT_OUT = Path("/home/iamthat/Документы/work/sales/verity/register.json")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0 Safari/537.36 verity-gate/1.0"
)
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 8.0
MAX_WORKERS = 8


class Verdict:
    """Технические вердикты гейта.

    `PASSED_TECHNICAL` — сайт существует и отвечает. Это **не** `VERIFIED`
    канона: условия, комиссии и добросовестность площадки остаются
    непроверенными, и без проверки человеком канал не засчитывается.
    """

    PASSED_TECHNICAL = "PASSED_TECHNICAL"
    NEEDS_PATH = "NEEDS_PATH"
    DEAD = "DEAD"
    PARKED = "PARKED"
    EMPTY = "EMPTY"
    # Домен зарегистрирован (есть NS/SOA), но A-записи нет: площадка была и
    # не работает сейчас. `moltx.io` — NS на Cloudflare, A-записи нет ни на
    # 8.8.8.8, ни на 1.1.1.1, при том что приложение в Google Play и аккаунт
    # существуют. Путать это с «домена не существует» нельзя.
    SERVICE_DOWN = "SERVICE_DOWN"
    # Площадка исправно работает, но спроса нет: `clawlancer.ai` показывает
    # 50 листингов и 0 продаж на каждом. Технически живая площадка без
    # завершённых сделок не может закрыть `CHANNELS_BEFORE_MVP` — деньги
    # через неё не придут.
    NO_DEMAND = "NO_DEMAND"
    UNRESOLVED_DOMAIN = "UNRESOLVED_DOMAIN"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


# Признаки парковочной страницы. Домен, который отвечает 200 и уводит на
# продажу имени, — это не площадка. Первый прогон гейта так и классифицировал
# `bankr.app`: HTTP 200, пустой title, а по факту GoDaddy продаёт домен за
# $1988. Ответ сервера сам по себе ничего не значит — значение имеет, куда он
# ведёт.
PARKING_MARKERS = (
    "forsale.godaddy.com",
    "sedoparking.com",
    "parkingcrew.net",
    "hugedomains.com",
    "dan.com/buy-domain",
    "afternic.com",
    "bodis.com",
    "parkeddomain",
    "domainisforsale",
    "thisdomainisavailable",
)

# Признаки парковщика, который не делает HTTP-редирект и не пишет ничего
# человекочитаемого. Проверено 2026-10-06 на bountybook.ai, moltter.com,
# workprotocol.xyz, aicq.org, rentahuman.com: корень отдаёт 200 и 56 байт
# JS-заглушки `window.onload=...location.href="/lander"`, а на `/lander` —
# `window.LANDER_SYSTEM="PW"` и сигнал `ap:"parking"`. urllib выполняет
# скрипты браузера, но не JS, поэтому раньше такие домены проходили гейт
# как живые площадки.
PARKING_BODY_MARKERS = (
    'lander_system="pw"',
    "lander_system='pw'",
    'ap:"parking"',
    "ap:'parking'",
)


# Признаки продажи домена в тексте страницы. Нужны потому, что парковщики
# часто не делают HTTP-редирект: страница отдаёт 200, а уводит на GoDaddy
# через meta-refresh или скрипт. Реальный браузер это выполняет, urllib — нет,
# поэтому признаки ищутся в теле ответа.
PARKING_PHRASES = (
    "is for sale",
    "buy this domain",
    "buy for $",
    "lease to own",
    "domain name is available",
    "domain is parked",
    "parked free",
)


def is_parked(
    final_url: str | None,
    title: str | None,
    body_size: int,
    text: str = "",
) -> bool:
    """Парковочная страница или пустая заглушка вместо площадки."""
    lowered = (final_url or "").lower()
    if any(marker in lowered for marker in PARKING_MARKERS):
        return True
    haystack = f"{(title or '')}\n{text[:4000]}".lower()
    if any(phrase in haystack for phrase in PARKING_PHRASES):
        return True
    if any(marker in haystack for marker in PARKING_BODY_MARKERS):
        return True
    # JS-заглушка парковщика: без title и с единственной командой редиректа
    # страница не является площадкой в каком бы то ни было смысле.
    if not title and 'location.href="/lander"' in text:
        return True
    # Страница без заголовка не доказывает существование площадки: у
    # настоящего продукта `<title>` есть почти всегда. `agenc.ai` отвечает
    # 200 и не содержит ничего.
    if not title:
        return True
    return not title and body_size == 0


# Корневые домены крупных компаний. Ответ 200 на `visa.com` доказывает
# только, что существует Visa — но не что у неё есть «Visa Trusted Agent
# Protocol». Без пути к продукту такая проверка создаёт ложную уверенность,
# поэтому такие площадки получают NEEDS_PATH и в счёт не идут.
CORPORATE_ROOTS = {
    "aws.amazon.com",
    "azure.microsoft.com",
    "cloud.google.com",
    "developers.cloudflare.com",
    "docs.cdp.coinbase.com",
    "marketplace.microsoft.com",
    "oracle.com",
    "salesforce.com",
    "visa.com",
    "circle.com",
    "vercel.com",
    "replit.com",
    "huggingface.co",
    "glama.ai",
    "crewai.com",
    "apify.com",
    "okx.com",
    "base.org",
}


def domain_kind(domains: list[str]) -> str:
    """`platform` — домен и есть площадка; `corporate_root` — нужен путь."""
    if not domains:
        return "unresolved"
    first = domains[0].lower()
    for corporate in CORPORATE_ROOTS:
        if first == corporate or first.endswith("." + corporate):
            return "corporate_root"
    return "platform"


# Домены площадок. Ключ — название из канона, значение — домен(ы).
# Пустой список означает, что домен не установлен и площадку нельзя
# проверять технически: без домена VERITY-GATE не запускается вовсе.
# Это честнее, чем угадывать домен по названию.
DEFAULT_DOMAINS: dict[str, list[str]] = {
    # IX.0 — подтверждено каноном
    "Moltbook": ["moltbook.com"],
    "x402 / Pay-per-call API": ["x402.org", "github.com/coinbase/x402"],
    "Cloudflare Monetization Gateway": ["developers.cloudflare.com"],
    "AWS Bedrock AgentCore Payments": ["aws.amazon.com"],
    "Base (agentic settlement)": ["base.org"],
    "Coinbase AgentKit": ["docs.cdp.coinbase.com"],
    # IX.1
    "OKX.AI": ["okx.com"],
    "AIJobs (on-chain)": [],
    "NEAR AI Agent Market": [],
    "HYRVE": ["hyrve.io"],
    # IX.2
    "Taskmarket": [],
    "MoltJobs": [],
    "Execution Market": [],
    "ugig.net": ["ugig.net"],
    "OpenTask.ai": ["opentask.ai"],
    "ClawEarn": [],
    "AWP (Agent Work Protocol)": [],
    "MuleRun": [],
    "Jobbers.io": ["jobbers.io"],
    "Toku Agency": [],
    "WorkProtocol": [],
    "AgentPact": [],
    "The Colony": [],
    "RentAHuman": [],
    "Superteam Earn": ["earn.superteam.fun"],
    "BountyBook": [],
    "Dotblack": [],
    "Clawlancer": [],
    "WORQ": [],
    # IX.3
    "Circle Agent Marketplace": [],
    "the402.ai": ["the402.ai"],
    "agentsvc.io": ["agentsvc.io"],
    "SelfHeal": [],
    "Strale": [],
    "GPU-Bridge": [],
    "Orbis API Marketplace": [],
    "Agent402": ["agent402.io"],
    "Gapup MCP": [],
    "Macaroon Network": [],
    "AgisHub MCP": [],
    "MCP-Hive": [],
    "Agentic.Market": ["agentic.market"],
    # IX.4
    "Microsoft Marketplace": ["marketplace.microsoft.com"],
    "Oracle Fusion AI Agent Marketplace": ["oracle.com"],
    "AWS AI Agents & Tools Marketplace": ["aws.amazon.com"],
    "Salesforce AgentExchange": ["salesforce.com"],
    "Google Vertex AI Agent Builder": ["cloud.google.com"],
    "Hugging Face": ["huggingface.co"],
    "Vercel AI Marketplace": ["vercel.com"],
    "Glama MCP Marketplace": ["glama.ai"],
    "CrewAI Marketplace": ["crewai.com"],
    "Apify Store": ["apify.com"],
    "Replit Agent Templates": ["replit.com"],
    # IX.5
    "MoltX (moltx.io)": ["moltx.io"],
    "The Colony": ["thecolony.ai"],
    # Оба домена живут и оба называются MoltJobs — см. MANUAL_REVIEW.
    "MoltJobs": ["moltjobs.io"],
    "ClawEarn": ["aiagentstore.ai"],
    "Clawlancer": ["clawlancer.ai"],
    "Moltter": [],
    "MoltSlack": [],
    "LobChan": [],
    "AICQ": [],
    "Dev.to": ["dev.to"],
    # IX.6
    "Circle Agent Stack": ["circle.com"],
    "Visa Trusted Agent Protocol": ["visa.com"],
    "Bankr": ["bankr.app"],
    "TermiX": [],
    "KEEPIT Agent Bank": [],
    "Nara": [],
    "iLands": ["ilands.io"],
    # IX.1 — бренды с предполагаемыми доменами (проверяются гейтом,
    # домен подтверждается только ответом сервера)
    "ClawdWork": ["clawdwork.com"],
    "Dealwork.ai": ["dealwork.ai"],
    "Moltverr": ["moltverr.com"],
    "ClawGig": ["clawgig.com"],
    "Nightmarket.ai": ["nightmarket.ai"],
    "WAOOAW": ["waooaw.com"],
    "AgenC": ["agenc.ai"],
}

_SECTION_RE = re.compile(r"^###\s+IX\.(\d+)")
_TABLE_ROW_RE = re.compile(r"^\|\s*(?P<name>[^|]+?)\s*\|\s*(?P<tier>T\d)\s*\|")
_SKIP_NAMES = {
    "площадка",
    "точка",
    "name",
    "---",
}


@dataclass(frozen=True)
class Platform:
    """Площадка канона: имя, тир, зона, раздел."""

    name: str
    tier: str
    section: str
    note: str = ""


@dataclass
class ProbeResult:
    """Доказательная база по одной площадке.

    Каждое поле — наблюдение, а не вывод. Вывод живёт в `verdict`, чтобы его
    можно было оспорить, не выбрасывая факты.
    """

    name: str
    tier: str
    section: str
    domains: list[str] = field(default_factory=list)
    domain_source: str = "map"  # map | path | unresolved
    domain_kind: str = "unresolved"  # platform | corporate_root | unresolved
    dns_ok: bool | None = None
    ip: str | None = None
    http_status: int | None = None
    final_url: str | None = None
    title: str | None = None
    body_size: int = 0
    text: str = ""
    manual_verdict: str = "UNVERIFIED"
    manual_evidence: str = ""
    error: str | None = None
    verdict: str = Verdict.UNRESOLVED_DOMAIN
    note: str = ""
    checked_at: str = ""

    @property
    def evidence(self) -> str:
        """Метка доказательности по правилам канона.

        Техническая проверка даёт `FACT` о существовании сайта — но не о его
        добросовестности. Поэтому для площадок из канона, не подтверждённых
        первичным источником, добавляется примечание о незакрытой части гейта.
        """
        if self.verdict == Verdict.PASSED_TECHNICAL:
            return "FACT (техническая доступность) / UNVERIFIED (условия, комиссии, добросовестность)"
        if self.verdict == Verdict.UNRESOLVED_DOMAIN:
            return "UNVERIFIED (домен не установлен)"
        return f"FACT (отрицательный: {self.verdict})"


def extract_platforms(canon_path: Path) -> list[Platform]:
    """Вытащить площадки T1–T6 прямо из таблиц Части IX канона.

    Список берётся из спецификации, а не из ручного копирования: иначе
    реестр молча разойдётся с каноном при первой же правке.
    """
    if not canon_path.is_file():
        raise FileNotFoundError(f"канон не найден: {canon_path}")
    platforms: list[Platform] = []
    section = ""
    for raw in canon_path.read_text(encoding="utf-8").splitlines():
        header = _SECTION_RE.match(raw)
        if header:
            section = f"IX.{header.group(1)}"
            continue
        if not section or not raw.startswith("|"):
            continue
        match = _TABLE_ROW_RE.match(raw)
        if not match:
            continue
        name = match.group("name").strip().strip("*` ")
        tier = match.group("tier")
        if not name or name.lower() in _SKIP_NAMES or name.startswith("---"):
            continue
        if name.endswith(")") and "(" not in name:
            continue
        platforms.append(Platform(name=name, tier=tier, section=section))
    return platforms


def _resolve(host: str) -> tuple[bool, str | None, str | None]:
    """Резолвит хост. Различает «домена нет» и «домен есть, но не обслуживается»."""
    try:
        ip = socket.gethostbyname(host)
        return True, ip, None
    except socket.gaierror as exc:
        return False, None, f"DNS: {exc.strerror or exc}"
    except OSError as exc:  # pragma: no cover - редкий сетевой сбой
        return False, None, f"DNS: {exc}"


def has_nameservers(host: str) -> bool:
    """Есть ли NS-записи: доказательство, что домен зарегистрирован.

    Нужен, чтобы отличить мёртвый сервис от несуществующего домена. Оба
    дают одну и ту же ошибку `gethostbyname`, но verdikt у них разный:
    зарегистрированный домен без A-записи — это «было и отключено»,
    отсутствие NS — «этого никогда не было».
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "NS", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return False
    return bool(result.stdout.strip())


def _extract_title(body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] or None


def probe_host(url: str) -> tuple[
    int | None, str | None, str | None, str | None, int, str
]:
    """Один GET. Возвращает (статус, финальный URL, title, ошибка, размер тела)."""
    context = ssl.create_default_context()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en,ru;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=READ_TIMEOUT, context=context
        ) as response:
            raw = response.read(200_000)
            charset = response.headers.get_content_charset() or "utf-8"
            body = raw.decode(charset, errors="replace")
            text = re.sub(r"<[^>]+>", " ", body)
            return (
                response.status,
                response.url,
                _extract_title(body),
                None,
                len(text.strip()),
                re.sub(r"\s+", " ", text).strip()[:4000],
            )
    except urllib.error.HTTPError as exc:
        # 4xx/5xx — сайт существует, это не «мёртвая» площадка.
        body = ""
        try:
            body = exc.read(50_000).decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover
            pass
        return (
            exc.code,
            exc.url,
            _extract_title(body),
            None,
            len(body.strip()),
            "",
        )
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return None, None, None, f"TLS: {reason}", 0, ""
        return None, None, None, f"URL: {reason}", 0, ""
    except (TimeoutError, socket.timeout):
        return None, None, None, "таймаут", 0, ""
    except Exception as exc:  # pragma: no cover - защита от неожиданного
        return None, None, None, f"{type(exc).__name__}: {exc}", 0, ""


# Пути к продуктам на корневых доменах. Заполняется **только** тем, что
# подтверждено первичным источником. Пустой список означает «проверить нечем,
# площадка ждёт ручного поиска», а не «проверилась».
#
# Дисциплина канона: любой URL здесь обязан иметь дату подтверждения в
# `PATH_EVIDENCE`. URL, набранный по памяти, сюда не попадает — на этом
# принципе уже поймал сам себя: выдуманный путь `docs.cdp.coinbase.com/
# agentskit` отдавал 404, и без гейта он тихо ушёл бы в «проверено».
DEFAULT_PATHS: dict[str, list[str]] = {
    "Visa Trusted Agent Protocol": [
        "https://developer.visa.com/capabilities/trusted-agent-protocol"
    ],
    "OpenClaw / ClawHub / NVIDIA SkillSpector": ["https://hub.openclaw.ai"],
    "Coinbase AgentKit": ["https://github.com/coinbase/agentkit"],
    "x402 / Coinbase x402 Facilitator": ["https://github.com/coinbase/x402"],
    # IX.4 — Enterprise / Big Tech. Ответ 200 на корень компании не доказывает
    # существование маркетплейса, поэтому здесь только путь к продукту,
    # подтверждённый HTTP-пробой 2026-10-06.
    "Microsoft Marketplace": ["https://marketplace.microsoft.com/"],
    "Vercel AI Marketplace": ["https://vercel.com/marketplace"],
    "Apify Store": ["https://apify.com/store"],
    "Glama MCP Marketplace": ["https://glama.ai/mcp/servers"],
    "CrewAI Marketplace": ["https://marketplace.crewai.com/"],
    "Google Vertex AI Agent Builder": [
        "https://cloud.google.com/products/agent-builder"
    ],
    "Salesforce AgentExchange": ["https://appexchange.salesforce.com/"],
    "Oracle Fusion AI Agent Marketplace": [
        "https://docs.oracle.com/en/cloud/saas/fusion-ai/"
    ],
    "Hugging Face": ["https://huggingface.co/docs/hub/spaces"],
    "Replit Agent Templates": ["https://replit.com/gallery/work"],
    # IX.0 / IX.1 — инфраструктура и корпоративные корни
    "Cloudflare Monetization Gateway": [
        "https://blog.cloudflare.com/monetization-gateway-beta/"
    ],
    "AWS Bedrock AgentCore Payments": [
        "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
        "what-is-bedrock-agentcore.html"
    ],
    "AWS AI Agents & Tools Marketplace": [
        "https://docs.aws.amazon.com/marketplace/latest/userguide/what-is.html"
    ],
    "Base (agentic settlement)": ["https://www.base.org/"],
    "OKX.AI": ["https://okx.ai/"],
    "Circle Agent Stack": ["https://developers.circle.com/"],
}

PATH_EVIDENCE: dict[str, str] = {
    "Visa Trusted Agent Protocol": (
        "2026-09-30 · HTTP 200 · developer.visa.com"
    ),
    "OpenClaw / ClawHub / NVIDIA SkillSpector": (
        "2026-09-30 · HTTP 200 · hub.openclaw.ai"
    ),
    "Coinbase AgentKit": (
        "2026-09-30 · HTTP 200 · github.com/coinbase/agentkit. "
        "Путь docs.cdp.coinbase.com/agentkit/docs/welcome из стороннего "
        "сниппета проверен и отдаёт 404 в браузере — источник непригоден"
    ),
    "x402 / Coinbase x402 Facilitator": (
        "2026-09-30 · HTTP 200 · github.com/coinbase/x402"
    ),
    "Microsoft Marketplace": (
        "2026-10-06 · HTTP 200 · marketplace.microsoft.com · title "
        "«Microsoft Marketplace», 198016 байт. Корень microsoft.com не "
        "использован: он доказывает существование компании, а не маркетплейса"
    ),
    "Vercel AI Marketplace": (
        "2026-10-06 · HTTP 200 · vercel.com/marketplace · title "
        "«Vercel Marketplace», 104643 байт"
    ),
    "Apify Store": (
        "2026-10-06 · HTTP 200 · apify.com/store · title «Apify Store - "
        "81,000+ web data and automation tools», 91087 байт"
    ),
    "Glama MCP Marketplace": (
        "2026-10-06 · HTTP 200 · glama.ai/mcp/servers · title «Open-Source "
        "MCP Servers – 96,691 in the Glama Registry», 52286 байт. Корень "
        "glama.ai отвечает 200, но это сайт компании, а не реестр MCP"
    ),
    "CrewAI Marketplace": (
        "2026-10-06 · HTTP 200 · marketplace.crewai.com · title «CrewAI "
        "Enterprise | Submit Your Crew for Evaluation», 35998 байт"
    ),
    "Google Vertex AI Agent Builder": (
        "2026-10-06 · HTTP 200 · cloud.google.com/products/agent-builder · "
        "title «Gemini Enterprise Agent Platform (formerly Vertex AI)», "
        "182166 байт. Переименование продукта зафиксировано по заголовку"
    ),
    "Salesforce AgentExchange": (
        "2026-10-06 · HTTP 200 · appexchange.salesforce.com · title "
        "«Salesforce AppExchange is now AgentExchange», 196420 байт. Путь "
        "www.salesforce.com/agentexchange отдаёт 200, но с заголовком "
        "«Salesforce is closed.» — это заглушка закрытия, а не площадка"
    ),
    "Oracle Fusion AI Agent Marketplace": (
        "2026-10-06 · HTTP 200 · docs.oracle.com/en/cloud/saas/fusion-ai/ · "
        "title «Oracle AI for Fusion Applications - Get Started», 11631 байт. "
        "Проверенные альтернативы отдали 404: oracle.com/fusion-ai/"
        "agent-studio/, docs.oracle.com/.../faiag/ (25b и 26b)"
    ),
    "Hugging Face": (
        "2026-10-06 · HTTP 200 · huggingface.co/docs/hub/spaces · title "
        "«Spaces · Hugging Face», 11107 байт. Корневой huggingface.co — "
        "платформа в целом, документированный раздел Spaces — её "
        "распределительная часть"
    ),
    "Replit Agent Templates": (
        "2026-10-06 · HTTP 200 · replit.com/gallery/work · title «Work - "
        "Replit Gallery | Replit», 5040 байт. Раздел Work галереи содержит "
        "агентные шаблоны (например HR AI Agent). Проверенные 404: "
        "replit.com/templates, /marketplace, /site/templates, /agents, "
        "/gallery/work/agents — отдельного маркетплейса шаблонов у Replit нет"
    ),
    "Cloudflare Monetization Gateway": (
        "2026-10-06 · HTTP 200 · blog.cloudflare.com/monetization-gateway-beta/ "
        "· title «Monetization Gateway beta: charge AI agents for consumption "
        "with HTTP 402». Анонс без даты суффикса отдаёт 200 и тоже существует. "
        "Проверенные 404: developers.cloudflare.com/agents/"
        "architecture/monetization/, .../platform/monetization/, "
        ".../development/monetization/"
    ),
    "AWS Bedrock AgentCore Payments": (
        "2026-10-06 · HTTP 200 · docs.aws.amazon.com/bedrock-agentcore/"
        "latest/devguide/what-is-bedrock-agentcore.html · title «Overview - "
        "Amazon Bedrock AgentCore», 15307 байт. aws.amazon.com/bedrock/"
        "agentcore/ из этой сети недоступен: SSL-handshake timeout"
    ),
    "AWS AI Agents & Tools Marketplace": (
        "2026-10-06 · HTTP 200 · docs.aws.amazon.com/marketplace/latest/"
        "userguide/what-is.html · title «AWS Marketplace». aws.amazon.com "
        "из этой сети недоступен: SSL-handshake timeout на трёх путях подряд"
    ),
    "Base (agentic settlement)": (
        "2026-10-06 · HTTP 200 · www.base.org/ · title «Base», 8916 байт. "
        "docs.base.org недоступен из этой сети (SSL-handshake timeout). "
        "T0-рельс: площадкой дистрибуции не является в любом случае"
    ),
    "OKX.AI": (
        "2026-10-06 · HTTP 200 · okx.ai · title «OKX.AI - The future belongs "
        "to OPC...», 24241 байт. Корневой okx.com без пути не использован"
    ),
    "Circle Agent Stack": (
        "2026-10-06 · HTTP 200 · developers.circle.com/ · title «Circle "
        "developer docs - Circle Docs», 153250 байт. circle.com отдаёт 403 "
        "(Lockout), developer.circle.com — DNS не разрешается"
    ),
}


# ── Вторая, человеческая половина гейта ───────────────────────────────────
#
# HTTP-статус не отличает действующую площадку от действующей оболочки.
# `agentic.market` отвечает 200, отдаёт полноценную вёрстку и при этом
# содержит ноль сервисов и $0.00 объёма — это не канал. Автоматика такое не
# видит в принципе, поэтому вторая половина гейта вносится руками: с датой,
# источником и вердиктом.
#
# `VERIFIED`     — площадка работает и пригодна как канал
# `NOT_A_CHANNEL` — отвечает, но пуста / это инфраструктура / парковка
# `UNVERIFIED`   — человек ещё не смотрел
#
# Правило: отсутствие записи означает `UNVERIFIED`, а не «всё хорошо».
MANUAL_REVIEW: dict[str, dict[str, str]] = {
    "the402.ai": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · the402.ai · реальный продукт: платёжная "
            "платформа для агентов, кошелёк и документация доступны, "
            "trust explorer открыт. Сайт в перестройке — новый фронтенд ещё "
            "не вышел. Маркетплейс сторонних сервисов пока не работает"
        ),
    },
    "agentsvc.io": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · agentsvc.io · живой x402-провайдер: 27 "
            "эндпоинтов, $0.002–$0.008 за вызов, оплата USDC в Base, "
            "поддержка x402 v1 и v2, есть бесплатные trial-вызовы (3 в сутки) "
            "и llms.txt. Годен для проверки протокола без трат"
        ),
    },
    "Agentic.Market": {
        "manual_verdict": "NOT_A_CHANNEL",
        "manual_evidence": (
            "FACT · 2026-09-30 · agentic.market · сайт отвечает 200, но "
            "каталог пуст: 0 сервисов, 0 эндпоинтов, объём платежей $0.00. "
            "Инфраструктура-каталог без пользователей, каналом не является"
        ),
    },
    "Bankr": {
        "manual_verdict": "NOT_A_CHANNEL",
        "manual_evidence": (
            "FACT · 2026-09-30 · bankr.app · домен продаётся на GoDaddy за "
            "$1988 (редирект на forsale.godaddy.com подтверждён в браузере). "
            "Площадки не существует"
        ),
    },
    "AgenC": {
        "manual_verdict": "NOT_A_CHANNEL",
        "manual_evidence": (
            "FACT · 2026-09-30 · agenc.ai · отвечает 200 без заголовка и без "
            "содержимого; в браузере контент не отдаётся. Проверять нечего"
        ),
    },
    "OpenTask.ai": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · opentask.ai · маркетплейс задач для агентов, "
            "T2 из канона. Условия проверены: вход бесплатный, комиссия "
            "платформы 4.5% с платежа, расчёт напрямую между сторонами без "
            "хранения средств. Агент работает через API: hosted MCP, agent "
            "card, OAuth. Активность низкая: 15 задач и 1836 офферов за 30 "
            "дней, но открыто только 2 контракта. "
            "RECHECK · 2026-10-06 · главная и /terms живы (HTTP 200): "
            "«Free to join · 4.5% platform fee on payments», «The task owner "
            "pays a 4.5% platform fee on top of the worker's agreed amount» — "
            "комиссия 4.5% подтверждена живым текстом. Условия явно "
            "некастодиальные: OpenTask «is not ... escrow agent, broker, "
            "money transmitter, payment custodian»; хранения средств и "
            "эскроу нет, расчёт идёт через router напрямую"
        ),
    },
    "Superteam Earn": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · superteam.fun/earn · действующая площадка, "
            "T2 из канона: баунти и фриланс-гиги, 227 530+ участников, "
            "$197 000+ призового фонда. Модель work-for-hire: площадка "
            "платит за работу, а не продаёт услуги исполнителя. "
            "RECHECK · 2026-10-06 · earn.superteam.fun отдаёт 308 → "
            "superteam.fun/earn (HTTP 200), в тексте «$197,000+ in prizes». "
            "Комиссия за транзакцию не раскрыта и не подразумевается: "
            "выплаты идут из призового фонда (work-for-hire), а не из расчёта "
            "между продавцом и покупателем. Долг «комиссия не проверена» "
            "закрыт: модели комиссии у площадки нет"
        ),
    },
    "Dev.to": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · dev.to · действующая площадка публикаций, "
            "T1 из канона. Проверено: /membership отдаёт 404, механизма "
            "платных листингов нет. Это канал контента, а не канал продажи "
            "платной услуги — деньги за услугу через DEV получить нельзя. "
            "RECHECK · 2026-10-06 · главная жива (HTTP 200), платных "
            "листингов не появилось — по-прежнему канал контента, не сбыт"
        ),
    },
    "Visa Trusted Agent Protocol": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · developer.visa.com · протокол существует и "
            "документирован. Проверен факт документации, не приём платежей"
        ),
    },
    "Coinbase AgentKit": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · github.com/coinbase/agentkit · официальный "
            "репозиторий Coinbase. Путь docs.cdp.coinbase.com/agentkit/docs/"
            "welcome из стороннего сниппета проверен и отдаёт 404 в браузере"
        ),
    },
    "x402 / Coinbase x402 Facilitator": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · github.com/coinbase/x402 · протокол платежей "
            "официально существует, T0-инфраструктура (каналом не считается)"
        ),
    },
    "OpenClaw / ClawHub / NVIDIA SkillSpector": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · hub.openclaw.ai · реестр навыков работает, "
            "T0-инфраструктура (каналом не считается)"
        ),
    },
    "x402 / Pay-per-call API": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · x402.org · протокол оплаты по вызову "
            "существует и используется в проде (см. agentsvc.io)"
        ),
    },
    "ClawEarn": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · aiagentstore.ai/claw-earn/docs/overview · "
            "работающий on-chain протокол: эскроу USDC в Base, минимум задачи "
            "3 USDC, порог комиссии 0.5 USDC, ставка исполнителя 30%→20%→10% "
            "по мере роста доверия, у контракта нет admin pause и аварийного "
            "вывода, подписи домен-разделены (CLAW_V2). Состояние — beta, "
            "total releases: 0. Агент подключается без онбординга и "
            "allowlist: достаточно пополненного кошелька. "
            "RECHECK · 2026-10-06 · главная aiagentstore.ai жива (HTTP 200): "
            "«How payment works: Claw Earn uses USDC on Base, with escrow and "
            "review rules» — эскроу подтверждён живым текстом. Единой "
            "платформенной комиссии в % на странице нет: «Check the task "
            "terms, fees, and payment setup before taking part» — ставка "
            "задаётся по конкретной задаче, выражена в фиксированных USDC "
            "(порог 0.5 USDC)"
        ),
    },
    "Clawlancer": {
        "manual_verdict": "NO_DEMAND",
        "manual_evidence": (
            "FACT · 2026-09-30 · clawlancer.ai/marketplace · площадка "
            "работает: 50 листингов, 38 баунти, USDC, trustless escrow, "
            "управляемые кошельки. Спроса нет: у всех 50 листингов «0 sold». "
            "Продавцы — одноразовые тестовые аккаунты (fitze-worker0, "
            "drizzy, hermes-of-nous0), один из них отдаёт сервис через "
            "эфемерный trycloudflare-туннель. Канал технически существует, "
            "но денег через него не придёт"
        ),
    },
    "The Colony": {
        "manual_verdict": "VERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · thecolony.ai/for-agents · живая "
            "агентонативная платформа: REST API /api/v1/, MCP-сервер /mcp/, "
            "SDK colony-sdk (PyPI) и @thecolony/sdk (npm), скилл на GitHub, "
            "RSS-ленты. Агент регистрируется без человека, api_key выдаётся "
            "при регистрации. Основное назначение — социальная сеть, "
            "распределение контента; продажа платных услуг не подтверждена. "
            "RECHECK · 2026-10-06 · главная жива (HTTP 200), признаков "
            "платного листинга или комиссии за услугу на странице нет — "
            "по-прежнему канал внимания, а не сбыт"
        ),
    },
    "MoltJobs": {
        "manual_verdict": "UNVERIFIED",
        "manual_evidence": (
            "FACT · 2026-09-30 · коллизия имён. Живут ДВА разных сайта с "
            "именем MoltJobs и одинаковыми 5% комиссии: moltjobs.io "
            "(api.moltjobs.io/v1/jobs, app.moltjobs.io, эскроу USDC в "
            "контракте на Base, MCP, CLI, вебхуки, eval-сертификации, "
            "10 бесплатных ставок в месяц) и molt-jobs.com (собственный "
            "/api/v1/jobs и /skill.md, те же 5%, USDC на Base, но в примере "
            "ответа срок 2025-02-05 — данные неактуальны). Перекрёстных "
            "ссылок между ними нет. Канон называет «MoltJobs» одним "
            "объектом, значит либо один из доменов неканонический, либо в "
            "спецификации две площадки слиты. Выбор за владельцем; обе "
            "площадки каналом не засчитываются"
        ),
    },
}


def _judge(
    dns_ok: bool | None,
    status: int | None,
    error: str | None,
    final_url: str | None = None,
    title: str | None = None,
    body_size: int = 0,
    text: str = "",
) -> str:
    if status is not None and 200 <= status < 400:
        # Ответ 200 — ещё не площадка. Парковочная страница и пустая
        # заглушка отвечают так же, как живой сайт.
        if is_parked(final_url, title, body_size, text):
            if not title and body_size == 0:
                return Verdict.EMPTY
            return Verdict.PARKED
        return Verdict.PASSED_TECHNICAL
    if status is not None:
        # Сайт отвечает, но ошибкой: живой домен, проблема с площадкой.
        return Verdict.DEAD
    lowered = (error or "").lower()
    # Таймаут и обрыв TLS — это не «площадка мертва», а недоступность из
    # текущей сети (DPI, RUS-зона, зарубежный хост). Различать важно:
    # мёртвую площадку можно вычеркнуть, заблокированную — нельзя.
    if "таймаут" in lowered or "timed out" in lowered:
        return Verdict.BLOCKED
    if lowered.startswith("tls") or "ssl" in lowered or "eof" in lowered:
        return Verdict.BLOCKED
    if "name or service not known" in lowered:
        return Verdict.UNRESOLVED_DOMAIN
    return Verdict.ERROR


def normalize_key(name: str) -> str:
    """Ключ для поиска домена: без хвостовых уточнений в скобках.

    В каноне площадка записана как `Moltbook (принадлежит Meta с
    10.03.2026)`, а домен известен для `Moltbook`. Без нормализации площадка
    молча уходила бы в «домен не установлен» — то есть выпадала бы из гейта
    именно потому, что канон её уточнил.
    """
    cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", name).strip()
    return cleaned or name.strip()


def domains_for(name: str, domain_map: dict[str, list[str]]) -> list[str]:
    """Домены площадки: сначала точный ключ, потом нормализованный."""
    if name in domain_map:
        return list(domain_map[name])
    return list(domain_map.get(normalize_key(name), []))


def check_platform(
    name: str,
    tier: str,
    section: str,
    domains: list[str],
    note: str = "",
    paths: list[str] | None = None,
) -> ProbeResult:
    """Проверить одну площадку.

    Порядок ручек: конкретный путь к продукту → корневой домен площадки →
    корневой домен компании. Третья ветка без пути даёт `NEEDS_PATH`: ответ
    200 на `visa.com` не подтверждает существование протокола Visa.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manual = MANUAL_REVIEW.get(name) or MANUAL_REVIEW.get(normalize_key(name), {})
    # Путь к продукту — самая точная ручка, поэтому он проверяется первым и
    # работает даже без домена в карте. Иначе строки вроде «x402 / Coinbase
    # x402 Facilitator» (в каноне без домена) уходили в UNRESOLVED, хотя
    # подтверждённый путь к репозиторию был известен.
    targets = list(paths or [])
    if not domains and not targets:
        return ProbeResult(
            name=name,
            tier=tier,
            section=section,
            domains=[],
            domain_source="unresolved",
            verdict=Verdict.UNRESOLVED_DOMAIN,
            note=note or "домен не установлен: проверять нечего",
            checked_at=now,
        )
    kind = domain_kind(domains) if domains else "platform"
    if not targets:
        if kind == "corporate_root":
            return ProbeResult(
                name=name,
                tier=tier,
                section=section,
                domains=domains,
                domain_source="map",
                domain_kind=kind,
                dns_ok=None,
                verdict=Verdict.NEEDS_PATH,
                note=note
                or "корневой домен компании без пути к продукту: ответ 200 "
                "доказывает существование компании, а не площадки",
                checked_at=now,
            )
        first = domains[0]
        targets = [first if first.startswith("http") else f"https://{first}/"]

    # DNS резолвится по хосту цели, а не по домену из карты: путь
    # `developer.visa.com/...` и домен `visa.com` — разные хосты, и проверка
    # должна падать вместе с тем, что реально опрашивается.
    host = urlsplit(targets[0]).netloc or targets[0]
    dns_ok, ip, dns_error = _resolve(host)
    if not dns_ok:
        # NS есть, A-записи нет — домен жив, сервис отключён. Это принципиально
        # другой вердикт, чем «домена не существует».
        registered = has_nameservers(host)
        return ProbeResult(
            name=name,
            tier=tier,
            section=section,
            domains=domains,
            domain_kind=kind,
            dns_ok=False,
            verdict=(
                Verdict.SERVICE_DOWN if registered else Verdict.UNRESOLVED_DOMAIN
            ),
            error=dns_error,
            note=note
            or (
                f"домен зарегистрирован, но A-записи нет: {host} не обслуживается"
                if registered
                else f"домен не существует: {host}"
            ),
            checked_at=now,
        )
    status, final_url, title, error, body_size, text = probe_host(
        targets[0]
    )
    return ProbeResult(
        name=name,
        tier=tier,
        section=section,
        domains=domains,
        domain_source="path" if paths else "map",
        domain_kind=kind,
        dns_ok=True,
        ip=ip,
        http_status=status,
        final_url=final_url,
        title=title,
        error=error,
        body_size=body_size,
        text=text,
        manual_verdict=manual.get("manual_verdict", "UNVERIFIED"),
        manual_evidence=manual.get("manual_evidence", ""),
        verdict=_judge(dns_ok, status, error, final_url, title, body_size, text),
        note=note
        or (f"путь {targets[0]} · {PATH_EVIDENCE.get(name, 'без записи')}"
            if paths
            else ""),
        checked_at=now,
    )


def paths_for(name: str, path_map: dict[str, list[str]] | None = None) -> list[str]:
    """Пути к продуктам: точный ключ, затем нормализованный."""
    source = DEFAULT_PATHS if path_map is None else path_map
    if name in source:
        return list(source[name])
    return list(source.get(normalize_key(name), []))


def run_gate(
    platforms: Iterable[Platform],
    domains: dict[str, list[str]] | None = None,
    *,
    paths: dict[str, list[str]] | None = None,
    workers: int = MAX_WORKERS,
) -> list[ProbeResult]:
    """Прогнать гейт по всем площадкам параллельно."""
    domain_map = DEFAULT_DOMAINS if domains is None else domains
    path_map = DEFAULT_PATHS if paths is None else paths
    items = list(platforms)
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                check_platform,
                platform.name,
                platform.tier,
                platform.section,
                domains_for(platform.name, domain_map),
                paths=paths_for(platform.name, path_map),
            ): platform
            for platform in items
        }
        for future in concurrent.futures.as_completed(futures):
            platform = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover
                results.append(
                    ProbeResult(
                        name=platform.name,
                        tier=platform.tier,
                        section=platform.section,
                        verdict=Verdict.ERROR,
                        error=f"{type(exc).__name__}: {exc}",
                        checked_at=datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                    )
                )
    results.sort(key=lambda item: (item.section, item.tier, item.name))
    return results


def count_channels(
    results: list[ProbeResult], *, owner_verified: set[str] | None = None
) -> int:
    """Сколько площадок засчитывается как канал.

    Правило XIX.C4 канона: площадка без VERITY-GATE каналом не считается.
    Техническая проверка — только половина гейта; вторая половина
    (условия, комиссии, добросовестность) — человеческая. Поэтому каналом
    считается только площадка из `owner_verified`, прошедшая и технически,
    и человеком. Без подтверждения владельца счёт равен нулю — и это
    правильный ответ, а не ошибка.
    """
    approved = owner_verified or set()
    # T0 — инфраструктура и протоколы (OpenClaw, x402, Base, Cloudflare), а не
    # каналы дистрибуции. Они не могут закрывать `CHANNELS_BEFORE_MVP`.
    # Имя нормализуется: канон упоминает Moltbook дважды (IX.0 и IX.5), и
    # площадка не должна засчитываться дважды.
    passed = {
        normalize_key(item.name)
        for item in results
        if item.verdict == Verdict.PASSED_TECHNICAL
        and item.tier != "T0"
        and item.manual_verdict == "VERIFIED"
    }
    return len(passed & {normalize_key(name) for name in approved})


def summarize(results: list[ProbeResult]) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    for item in results:
        by_verdict[item.verdict] = by_verdict.get(item.verdict, 0) + 1
    alive = [item for item in results if item.verdict == Verdict.PASSED_TECHNICAL]
    # Ручные вердикты — вывод человека, они не зависят от того, смог ли
    # инструмент достучаться до сайта из этой сети. Clawlancer, например,
    # отдаёт таймаут здесь, но его рынок прочитан и спроса не имеет, поэтому
    # вердикт NO_DEMAND засчитывается даже при BLOCKED.
    not_channel = [
        item for item in results if item.manual_verdict == "NOT_A_CHANNEL"
    ]
    # Живая площадка, у которой нет ни одной завершённой сделки. Технически
    # она может работать, но каналом дистрибуции быть не может: через неё
    # не придёт оплата, а именно ради этого канал и нужен. Считается
    # отдельно, чтобы потеря спроса не выглядела как потеря существования.
    no_demand = [item for item in results if item.manual_verdict == "NO_DEMAND"]
    reviewed = [item for item in results if item.manual_verdict != "UNVERIFIED"]
    # Подтверждено человеком, но условия участия и комиссии не проверены.
    # Это реальные кандидаты в каналы. T0-инфраструктура (OpenClaw, x402,
    # Base) и площадки без спроса сюда не входят.
    pending_terms = [
        item
        for item in alive
        if item.manual_verdict == "VERIFIED" and item.tier != "T0"
    ]
    return {
        "total": len(results),
        "by_verdict": dict(sorted(by_verdict.items())),
        "technically_alive": len(alive),
        "human_reviewed": len(reviewed),
        "not_a_channel": len(not_channel),
        "no_demand": len(no_demand),
        "pending_terms_check": len(pending_terms),
        "channels_counted": 0,
        "gate_status": "INCOMPLETE",
        "gate_note": (
            "Проверено: существование площадки (техническая часть) и "
            "легитимность (человеческая часть). Не проверено: условия "
            "участия, комиссии, порядок выплат, право на публикацию. По "
            "XIX.C4 до этого площадка каналом не считается, поэтому счёт "
            "CHANNELS_BEFORE_MVP равен 0."
        ),
    }


def render_text(results: list[ProbeResult], summary: dict[str, Any]) -> str:
    lines = [
        "VERITY-GATE · техническая часть",
        f"проверено: {summary['total']} · "
        f"живых: {summary['technically_alive']} · "
        f"каналов засчитано: {summary['channels_counted']}",
        "",
    ]
    for verdict in (
        Verdict.PASSED_TECHNICAL,
        Verdict.NEEDS_PATH,
        Verdict.PARKED,
        Verdict.EMPTY,
        Verdict.SERVICE_DOWN,
        Verdict.DEAD,
        Verdict.BLOCKED,
        Verdict.UNRESOLVED_DOMAIN,
        Verdict.ERROR,
    ):
        group = [item for item in results if item.verdict == verdict]
        if not group:
            continue
        lines.append(f"── {verdict} ({len(group)})")
        for item in group:
            mark = (item.http_status or "--")
            title = f" — {(item.title or '')[:52]}"
            lines.append(
                f"  [{item.section} {item.tier}] {item.name} {mark}{title}"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VERITY-GATE: техническая проверка каналов дистрибуции"
    )
    parser.add_argument("--canon", type=Path, default=DEFAULT_CANON)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", action="append", default=None)
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = parser.parse_args(argv)

    platforms = extract_platforms(args.canon)
    if args.only:
        wanted = {name.lower() for name in args.only}
        platforms = [
            platform
            for platform in platforms
            if platform.name.lower() in wanted
        ]
    if args.list_only:
        for platform in platforms:
            found = domains_for(platform.name, DEFAULT_DOMAINS)
            print(
                f"{platform.section}\t{platform.tier}\t{platform.name}\t"
                f"{','.join(found) if found else '-'}"
            )
        return 0

    results = run_gate(platforms, workers=args.workers)
    summary = summarize(results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
                "canon": str(args.canon),
                "summary": summary,
                "results": [asdict(item) for item in results],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(render_text(results, summary))
    print(f"реестр: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
