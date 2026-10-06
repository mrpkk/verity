"""Тесты VERITY-GATE.

Инструмент проверки каналов дистрибуции опасен именно своими ложными
уверенными вердиктами: площадка, помеченная живой, попадает в счёт
`CHANNELS_BEFORE_MVP` и дальше в маркетинг. Поэтому тесты бьют не по
сети, а по логике вердиктов — она обязана отличать «живую площадку» от
«живого корневого домена компании» и от «заблокированной из этой сети».

Сеть не используется: `probe_host` подменён, проверяются чистые решения.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# `verity_gate.py` живёт рядом с этим репозиторием (в каталоге `sales/`), а не
# внутри `verity/`. Раньше тест подставлял только `verity/`, из-за чего после
# переноса на диск ŚRUTI модуль не импортировался и сборка падала. Ищем
# каталог, где файл действительно лежит, — устойчиво к обоим вариантам.
_HERE = Path(__file__).resolve().parent.parent
for _candidate in (_HERE, _HERE.parent):
    if (_candidate / "verity_gate.py").is_file() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

import verity_gate  # noqa: E402

from verity_gate import (  # noqa: E402
    Verdict,
    _judge,
    check_platform,
    count_channels,
    domain_kind,
    domains_for,
    extract_platforms,
    normalize_key,
    paths_for,
    summarize,
)

CANON = Path("/home/iamthat/Документы/work/projectBooks/tmpSPEC/roadmapV4.md")


class TestCanonParsing:
    def test_platforms_are_read_from_canon_not_hand_copied(self) -> None:
        """Список обязан идти из спецификации, иначе реестр разойдётся с ней."""
        platforms = extract_platforms(CANON)
        assert len(platforms) > 50
        names = {platform.name for platform in platforms}
        assert "Moltbook" in names
        assert "Visa Trusted Agent Protocol" in names
        assert "Superteam Earn" in names

    def test_tiers_are_preserved(self) -> None:
        platforms = {p.name: p.tier for p in extract_platforms(CANON)}
        assert platforms["Moltbook"] == "T1"
        assert platforms["Visa Trusted Agent Protocol"] == "T5"
        assert platforms["Superteam Earn"] == "T2"

    def test_missing_canon_raises_instead_of_empty_register(self) -> None:
        """Пустой реестр из-за неверного пути — худший вид молчаливой ошибки."""
        with pytest.raises(FileNotFoundError):
            extract_platforms(Path("/nonexistent/canon.md"))


class TestKeyNormalization:
    def test_parenthetical_is_stripped(self) -> None:
        assert normalize_key("Moltbook (принадлежит Meta с 10.03.2026)") == (
            "Moltbook"
        )

    def test_domain_lookup_uses_normalized_key(self) -> None:
        """Канон уточнил название — площадка не должна выпасть из гейта."""
        found = domains_for(
            "Moltbook (принадлежит Meta с 10.03.2026)",
            {"Moltbook": ["moltbook.com"]},
        )
        assert found == ["moltbook.com"]

    def test_exact_key_wins(self) -> None:
        found = domains_for("MoltX (moltx.io)", {"MoltX (moltx.io)": ["a"]})
        assert found == ["a"]

    def test_paths_also_normalize(self) -> None:
        assert paths_for("Moltbook (Meta)", {"Moltbook": ["u"]}) == ["u"]


class TestVerdictLogic:
    def test_200_is_passed(self) -> None:
        assert (
            _judge(True, 200, None, "https://x.io/", "X platform", 5_000)
            == Verdict.PASSED_TECHNICAL
        )

    def test_error_codes_are_dead_not_passed(self) -> None:
        """404 на существующем домене — площадка мертва, а не жива."""
        assert _judge(True, 404, None) == Verdict.DEAD
        assert _judge(True, 403, None) == Verdict.DEAD

    def test_timeout_is_blocked_not_dead(self) -> None:
        """Таймаут из РФ не доказывает, что площадка мертва."""
        assert _judge(True, None, "таймаут") == Verdict.BLOCKED
        assert _judge(True, None, "URL: timed out") == Verdict.BLOCKED

    def test_tls_failure_is_blocked(self) -> None:
        assert _judge(True, None, "TLS: bad cert") == Verdict.BLOCKED
        assert _judge(True, None, "URL: [SSL: UNEXPECTED_EOF] EOF") == (
            Verdict.BLOCKED
        )

    def test_unknown_host_is_unresolved(self) -> None:
        assert _judge(
            True, None, "URL: Name or service not known"
        ) == Verdict.UNRESOLVED_DOMAIN


class TestCorporateRoot:
    def test_corporate_roots_are_detected(self) -> None:
        assert domain_kind(["visa.com"]) == "corporate_root"
        assert domain_kind(["docs.cdp.coinbase.com"]) == "corporate_root"
        assert domain_kind(["aws.amazon.com"]) == "corporate_root"

    def test_dedicated_domain_is_platform(self) -> None:
        assert domain_kind(["the402.ai"]) == "platform"
        assert domain_kind(["moltx.io"]) == "platform"

    def test_corporate_root_without_path_is_needs_path(self) -> None:
        """Ответ 200 на visa.com не подтверждает существование протокола.

        Это главная ловушка гейта: без этой проверки корпоративный сайт
        засчитывался бы как подтверждённая площадка.
        """
        result = check_platform(
            "Oracle Fusion AI Agent Marketplace",
            "T4",
            "IX.4",
            ["oracle.com"],
        )
        assert result.verdict == Verdict.NEEDS_PATH
        assert result.domain_kind == "corporate_root"
        assert result.http_status is None

    def test_corporate_root_with_path_is_checked(self) -> None:
        checked: list[str] = []

        def fake_probe(url: str):
            checked.append(url)
            return 200, url, "Trusted Agent Protocol", None, 12_000, "Trusted"

        import verity_gate

        original = verity_gate.probe_host
        verity_gate.probe_host = fake_probe
        try:
            result = check_platform(
                "Visa Trusted Agent Protocol",
                "T5",
                "IX.6",
                ["visa.com"],
                paths=["https://developer.visa.com/capabilities/trusted-agent-protocol"],
            )
        finally:
            verity_gate.probe_host = original

        assert checked == [
            "https://developer.visa.com/capabilities/trusted-agent-protocol"
        ]
        assert result.verdict == Verdict.PASSED_TECHNICAL
        assert result.domain_source == "path"

    def test_every_path_has_evidence_record(self) -> None:
        """Правило канона: URL без даты подтверждения в гейт не попадает."""
        from verity_gate import DEFAULT_PATHS, PATH_EVIDENCE

        for name in DEFAULT_PATHS:
            assert name in PATH_EVIDENCE, f"{name}: путь без даты подтверждения"
            assert "2026" in PATH_EVIDENCE[name]


class TestChannelCount:
    def _results(self, verdicts: dict[str, str]):
        from verity_gate import ProbeResult

        return [
            ProbeResult(
                name=name,
                tier="T1",
                section="IX.5",
                verdict=verdict,
                # Технически живая и проверенная человеком площадка —
                # единственный вид, который вообще может стать каналом.
                manual_verdict="VERIFIED",
                checked_at="2026-09-30T00:00:00+00:00",
            )
            for name, verdict in verdicts.items()
        ]

    def test_technical_pass_alone_counts_nothing(self) -> None:
        """Правило XIX.C4: без полного гейта каналов ноль, даже если сайт жив."""
        results = self._results(
            {"Dev.to": Verdict.PASSED_TECHNICAL, "Moltbook": Verdict.DEAD}
        )
        assert count_channels(results) == 0

    def test_channel_counts_only_with_owner_confirmation(self) -> None:
        results = self._results(
            {
                "Dev.to": Verdict.PASSED_TECHNICAL,
                "Moltbook": Verdict.PASSED_TECHNICAL,
            }
        )
        assert count_channels(results) == 0
        assert count_channels(results, owner_verified={"Dev.to"}) == 1

    def test_unverified_platform_cannot_be_counted(self) -> None:
        """Площадка, не прошедшая техчасть, не считается даже с подтверждением."""
        results = self._results({"Superteam Earn": Verdict.NEEDS_PATH})
        assert count_channels(results, owner_verified={"Superteam Earn"}) == 0


class TestSummary:
    def test_gate_is_incomplete_by_design(self) -> None:
        from verity_gate import ProbeResult

        results = [
            ProbeResult(
                name="Dev.to",
                tier="T1",
                section="IX.5",
                verdict=Verdict.PASSED_TECHNICAL,
                checked_at="2026-09-30T00:00:00+00:00",
            )
        ]
        summary = summarize(results)
        assert summary["technically_alive"] == 1
        assert summary["channels_counted"] == 0
        assert summary["gate_status"] == "INCOMPLETE"


class TestParkedDomain:
    """Парковочный домен отвечает 200 и не является площадкой.

    Реальный случай из первого прогона: `bankr.app` вернул HTTP 200 с пустым
    title, и гейт засчитал его как живую площадку T5. По факту домен продаётся
    на GoDaddy за $1988. Если такое попадает в счёт `CHANNELS_BEFORE_MVP`, то
    счёт считает выдуманные каналы.
    """

    def test_parking_redirect_is_detected(self) -> None:
        from verity_gate import is_parked

        parked = is_parked(
            "https://forsale.godaddy.com/forsale/bankr.app?x=1", None, 4000
        )
        assert parked is True

    def test_sale_title_is_detected(self) -> None:
        from verity_gate import is_parked

        assert is_parked("https://bankr.app/", "bankr.app is for sale", 4000)
        assert is_parked("https://x.io/", "This domain is parked", 100)

    def test_empty_page_is_flagged(self) -> None:
        from verity_gate import is_parked

        assert is_parked("https://agenc.ai/", None, 0) is True

    def test_page_without_title_is_not_a_platform(self) -> None:
        """200 без `<title>` не доказывает площадку — так ведёт себя заглушка."""
        from verity_gate import is_parked

        assert is_parked("https://agenc.ai/", None, 1_200) is True

    def test_meta_refresh_parking_is_detected(self) -> None:
        """Парковщик отдаёт 200 без редиректа и продаёт домен в тексте.

        Реальный случай `bankr.app`: urllib не выполняет meta-refresh, поэтому
        финальный URL остаётся доменом, и распознать площадку можно только по
        содержимому.
        """
        from verity_gate import is_parked

        body = (
            "Bankr.app is for sale Buy for $1,988 or Lease to Own "
            "Safe & secure transactions"
        )
        assert is_parked("https://bankr.app/", None, len(body), body) is True

    def test_parked_body_cannot_reach_passed(self) -> None:
        body = "bankr.app is for sale - Buy for $1,988"
        assert _judge(True, 200, None, "https://bankr.app/", None, len(body), body) == (
            Verdict.PARKED
        )

    def test_real_platform_is_not_flagged(self) -> None:
        from verity_gate import is_parked

        assert (
            is_parked(
                "https://the402.ai/",
                "the402: the purchasing platform for AI agents",
                20_000,
            )
            is False
        )

    def test_parked_lander_redirect_is_detected(self) -> None:
        """Парковщик без URL-редиректа: 200 + `<title>` отсутствует + скрипт
        уводит на `/lander`.

        Реальный случай 2026-10-06: `bountybook.ai`, `moltter.com`,
        `workprotocol.xyz`, `aicq.org`, `rentahuman.com`, `moltbook.com`
        отдавали ровно это. Тело — 56 байт JS-заглушка, а на самой странице
        `/lander` лежит `window.LANDER_SYSTEM="PW"` и `ap:"parking"`.
        Без этого признака гейт засчитывал мёртвые домены как живые.
        """
        from verity_gate import is_parked

        stub = 'window.onload=function(){window.location.href="/lander"}'
        assert is_parked("https://bountybook.ai/", None, len(stub), stub) is True

        lander = 'window.LANDER_SYSTEM="PW" window._trfd.push({ap:"parking"})'
        assert is_parked("https://bountybook.ai/lander", None, len(lander), lander) is True

    def test_parked_200_is_not_passed(self) -> None:
        """200 от парковщика не должен доходить до PASSED_TECHNICAL."""
        assert (
            _judge(True, 200, None, "https://forsale.godaddy.com/forsale/b", None, 4000)
            == Verdict.PARKED
        )

    def test_empty_page_is_not_passed(self) -> None:
        assert _judge(True, 200, None, "https://agenc.ai/", None, 0) == (
            Verdict.EMPTY
        )

    def test_live_platform_still_passes(self) -> None:
        assert _judge(True, 200, None, "https://the402.ai/", "the402", 20_000) == (
            Verdict.PASSED_TECHNICAL
        )

    def test_parked_platform_cannot_be_counted_as_channel(self) -> None:
        from verity_gate import ProbeResult

        results = [
            ProbeResult(
                name="Bankr",
                tier="T5",
                section="IX.6",
                verdict=Verdict.PARKED,
                checked_at="2026-09-30T00:00:00+00:00",
            )
        ]
        assert count_channels(results, owner_verified={"Bankr"}) == 0


class TestPathWithoutDomain:
    """Подтверждённый путь работает и для строк канона без домена.

    В каноне «x402 / Coinbase x402 Facilitator» и «OpenClaw / ClawHub» идут
    без домена, но путь к продукту известен. Ранний выход по пустому `domains`
    отправлял их в UNRESOLVED_DOMAIN, то есть гейт выбрасывал проверяемое.
    """

    def test_path_is_used_when_domain_missing(self) -> None:
        result = check_platform(
            "x402 / Coinbase x402 Facilitator",
            "T0",
            "IX.0",
            [],
            paths=["https://github.com/coinbase/x402"],
        )
        assert result.verdict != Verdict.UNRESOLVED_DOMAIN
        assert result.domain_source == "path"

    def test_missing_both_stays_unresolved(self) -> None:
        result = check_platform("HYRVE", "T3", "IX.1", [])
        assert result.verdict == Verdict.UNRESOLVED_DOMAIN

    def test_path_targets_expected_url(self) -> None:
        checked: list[str] = []

        def fake_probe(url: str):
            checked.append(url)
            return 200, url, "x402", None, 9_000, "x402"

        import verity_gate

        original = verity_gate.probe_host
        verity_gate.probe_host = fake_probe
        try:
            check_platform(
                "x402 / Coinbase x402 Facilitator",
                "T0",
                "IX.0",
                [],
                paths=["https://github.com/coinbase/x402"],
            )
        finally:
            verity_gate.probe_host = original

        assert checked == ["https://github.com/coinbase/x402"]


class TestTierAndDedupe:
    """T0 — инфраструктура, а не канал дистрибуции; дубли не считаются дважды."""

    def _r(self, name: str, tier: str):
        from verity_gate import ProbeResult

        return ProbeResult(
            name=name,
            tier=tier,
            section="IX.0",
            verdict=Verdict.PASSED_TECHNICAL,
            # Канал засчитывается только после ручной проверки: без неё
            # технически живая площадка остаётся неподтверждённой.
            manual_verdict="VERIFIED",
            checked_at="2026-09-30T00:00:00+00:00",
        )

    def test_t0_infrastructure_is_not_a_channel(self) -> None:
        results = [self._r("x402 / Coinbase x402 Facilitator", "T0")]
        assert count_channels(results, owner_verified={
            "x402 / Coinbase x402 Facilitator"
        }) == 0

    def test_duplicate_rows_count_once(self) -> None:
        """Moltbook в каноне идёт в IX.0 и IX.5 — это одна площадка."""
        results = [self._r("Moltbook", "T1"), self._r("Moltbook (Meta)", "T1")]
        assert count_channels(results, owner_verified={"Moltbook"}) == 1

    def test_real_tier_counts(self) -> None:
        results = [self._r("the402.ai", "T3")]
        assert count_channels(results, owner_verified={"the402.ai"}) == 1


def _r(
    name: str,
    verdict: str,
    manual_verdict: str = "UNVERIFIED",
    tier: str = "T3",
):
    """Собрать ProbeResult для проверки счётчиков."""
    return verity_gate.ProbeResult(
        name=name,
        tier=tier,
        section="IX.3",
        verdict=verdict,
        manual_verdict=manual_verdict,
        checked_at="2026-09-30T00:00:00+00:00",
    )


class TestNoDemand:
    """Площадка без сделок не должна выдавать себя за канал дистрибуции."""

    def test_clawlancer_is_flagged_no_demand(self):
        entry = verity_gate.MANUAL_REVIEW["Clawlancer"]
        assert entry["manual_verdict"] == "NO_DEMAND"
        assert "0 sold" in entry["manual_evidence"]

    def test_no_demand_survives_blocked_probe(self):
        """Ручной вывод не зависит от того, достучался ли инструмент.

        Clawlancer отдаёт таймаут из этой сети, но его рынок прочитан:
        50 листингов, 0 продаж. Вердикт NO_DEMAND обязан сохраниться,
        иначе сетевой сбой маскирует рыночный факт.
        """
        results = [
            _r("Clawlancer", Verdict.BLOCKED, manual_verdict="NO_DEMAND"),
        ]
        summary = verity_gate.summarize(results)
        assert summary["no_demand"] == 1
        assert summary["technically_alive"] == 0

    def test_no_demand_counted_separately(self):
        results = [
            _r("Clawlancer", Verdict.PASSED_TECHNICAL, manual_verdict="NO_DEMAND"),
            _r("Opentask", Verdict.PASSED_TECHNICAL, manual_verdict="VERIFIED"),
        ]
        summary = verity_gate.summarize(results)
        assert summary["no_demand"] == 1
        # Живая площадка без спроса не идёт в кандидаты на проверку условий.
        assert summary["pending_terms_check"] == 1

    def test_owner_cannot_approve_no_demand_platform(self):
        """Ключевой тест: подтверждение владельца не превращает пустую
        площадку в канал."""
        results = [
            _r("Clawlancer", Verdict.PASSED_TECHNICAL, manual_verdict="NO_DEMAND"),
        ]
        assert verity_gate.count_channels(results, owner_verified={"Clawlancer"}) == 0

    def test_owner_cannot_approve_parking_or_not_a_channel(self):
        results = [
            _r("AgenC", Verdict.PARKED, manual_verdict="NOT_A_CHANNEL"),
            _r("Bankr", Verdict.PARKED, manual_verdict="NOT_A_CHANNEL"),
            _r("AgenticMarket", Verdict.PASSED_TECHNICAL, manual_verdict="NOT_A_CHANNEL"),
        ]
        assert verity_gate.count_channels(
            results, owner_verified={"AgenC", "Bankr", "AgenticMarket"}
        ) == 0

    def test_owner_approval_counts_verified_platform(self):
        results = [
            _r("Opentask", Verdict.PASSED_TECHNICAL, manual_verdict="VERIFIED"),
        ]
        assert verity_gate.count_channels(results, owner_verified={"Opentask"}) == 1


class TestManualReviewHalf:
    """Вторая половина гейта: ручная проверка с датой и источником.

    HTTP-статус не отличает канал от действующей оболочки: `agentic.market`
    отдаёт полноценную вёрстку, ноль сервисов и $0.00 объёма. Такие случаи
    автоматика не видит, поэтому ручные вердикты обязаны быть датированы и
    обоснованы.
    """

    def test_every_manual_verdict_has_dated_evidence(self) -> None:
        from verity_gate import MANUAL_REVIEW

        assert MANUAL_REVIEW, "ручная половина гейта пуста — гейт не сделан"
        for name, entry in MANUAL_REVIEW.items():
            evidence = entry.get("manual_evidence", "")
            assert entry.get("manual_verdict") in {
                "VERIFIED",
                "NOT_A_CHANNEL",
                "NO_DEMAND",
                "UNVERIFIED",
            }, f"{name}: неизвестный вердикт"
            assert evidence.startswith("FACT · "), f"{name}: нет метки FACT"
            assert "2026-" in evidence, f"{name}: нет даты"
            # Источник — реальное имя хоста, а не перечисление расширений:
            # https://docs.python.org/3/library/re.html
            import re

            host = re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", evidence)
            assert host, f"{name}: нет источника"

    def test_parked_platform_is_marked_not_a_channel(self) -> None:
        from verity_gate import MANUAL_REVIEW

        assert MANUAL_REVIEW["Bankr"]["manual_verdict"] == "NOT_A_CHANNEL"

    def test_empty_shell_is_marked_not_a_channel(self) -> None:
        from verity_gate import MANUAL_REVIEW

        assert (
            MANUAL_REVIEW["Agentic.Market"]["manual_verdict"] == "NOT_A_CHANNEL"
        )

    def test_parking_and_empty_findings_are_recorded(self) -> None:
        """Реальные находки обязаны остаться в реестре как доказательства."""
        from verity_gate import MANUAL_REVIEW

        assert "1988" in MANUAL_REVIEW["Bankr"]["manual_evidence"]
        assert "$0.00" in MANUAL_REVIEW["Agentic.Market"]["manual_evidence"]

    def test_summary_separates_technical_and_human(self) -> None:
        from verity_gate import ProbeResult, Verdict, summarize

        def make(name: str, verdict: str, manual: str, tier: str = "T3"):
            return ProbeResult(
                name=name,
                tier=tier,
                section="IX.3",
                verdict=verdict,
                manual_verdict=manual,
                checked_at="2026-09-30T00:00:00+00:00",
            )

        results = [
            make("the402.ai", Verdict.PASSED_TECHNICAL, "VERIFIED"),
            make("Agentic.Market", Verdict.PASSED_TECHNICAL, "NOT_A_CHANNEL"),
            make("HYRVE", Verdict.UNRESOLVED_DOMAIN, "UNVERIFIED"),
        ]
        summary = summarize(results)
        assert summary["technically_alive"] == 2
        assert summary["human_reviewed"] == 2
        assert summary["not_a_channel"] == 1
        assert summary["pending_terms_check"] == 1
        # Существование подтверждено, но условия не проверены → каналов 0.
        assert summary["channels_counted"] == 0
        assert summary["gate_status"] == "INCOMPLETE"


class TestPendingTermsExcludesInfra:
    """T0-инфраструктура не может стать каналом ни при каких условиях."""

    def test_t0_not_in_pending_terms(self) -> None:
        from verity_gate import ProbeResult, Verdict, summarize

        results = [
            ProbeResult(
                name="x402 / Coinbase x402 Facilitator",
                tier="T0",
                section="IX.0",
                verdict=Verdict.PASSED_TECHNICAL,
                manual_verdict="VERIFIED",
                checked_at="2026-09-30T00:00:00+00:00",
            ),
            ProbeResult(
                name="the402.ai",
                tier="T3",
                section="IX.3",
                verdict=Verdict.PASSED_TECHNICAL,
                manual_verdict="VERIFIED",
                checked_at="2026-09-30T00:00:00+00:00",
            ),
        ]
        summary = summarize(results)
        assert summary["pending_terms_check"] == 1


class TestServiceDownVsUnresolved:
    """Домен без A-записи и несуществующий домен — разные вердикты.

    `moltx.io`: NS на Cloudflare, но A-записи нет ни на 8.8.8.8, ни на
    1.1.1.1, при живом приложении в Google Play. Называть это
    «домен не найден» — значит потерять площадку, которая была и может
    вернуться.
    """

    def test_registered_domain_without_a_record_is_service_down(self) -> None:
        import verity_gate

        original_resolve = verity_gate._resolve
        original_ns = verity_gate.has_nameservers
        verity_gate._resolve = lambda host: (False, None, "DNS: no address")
        verity_gate.has_nameservers = lambda host: True
        try:
            result = verity_gate.check_platform("MoltX (moltx.io)", "T1", "IX.5", ["moltx.io"])
        finally:
            verity_gate._resolve = original_resolve
            verity_gate.has_nameservers = original_ns

        assert result.verdict == Verdict.SERVICE_DOWN
        assert "не обслуживается" in result.note

    def test_nonexistent_domain_stays_unresolved(self) -> None:
        import verity_gate

        original_resolve = verity_gate._resolve
        original_ns = verity_gate.has_nameservers
        verity_gate._resolve = lambda host: (False, None, "DNS: NXDOMAIN")
        verity_gate.has_nameservers = lambda host: False
        try:
            result = verity_gate.check_platform("HYRVE", "T3", "IX.1", ["hyrve.invalid"])
        finally:
            verity_gate._resolve = original_resolve
            verity_gate.has_nameservers = original_ns

        assert result.verdict == Verdict.UNRESOLVED_DOMAIN

    def test_service_down_is_not_a_channel(self) -> None:
        from verity_gate import ProbeResult

        results = [
            ProbeResult(
                name="MoltX",
                tier="T1",
                section="IX.5",
                verdict=Verdict.SERVICE_DOWN,
                checked_at="2026-09-30T00:00:00+00:00",
            )
        ]
        assert count_channels(results, owner_verified={"MoltX"}) == 0
