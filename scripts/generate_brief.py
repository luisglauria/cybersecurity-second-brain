"""Generate and render the daily cybersecurity briefing.

The script is deliberately dependency-light so it can run on a stock
GitHub-hosted runner. It treats external feeds as untrusted input, keeps a
small allowlist, escapes generated HTML, and preserves the previous report if
the collection or model step fails.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
SITE_DIR = ROOT / "site"
STATE_PATH = SITE_DIR / "briefing.json"
INDEX_PATH = SITE_DIR / "index.html"
TIMEZONE = ZoneInfo("America/Sao_Paulo")
USER_AGENT = "cybersecurity-second-brain/1.0 (+GitHub Actions)"


def now_local() -> dt.datetime:
    return dt.datetime.now(TIMEZONE).replace(microsecond=0)


def clean_text(value: object, limit: int = 700) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def child_text(node: ET.Element, names: tuple[str, ...]) -> str:
    for child in list(node):
        tag = child.tag.rsplit("}", 1)[-1].lower()
        if tag in names:
            return clean_text(child.text)
    return ""


def child_link(node: ET.Element) -> str:
    for child in list(node):
        tag = child.tag.rsplit("}", 1)[-1].lower()
        if tag == "link":
            href = child.attrib.get("href") or child.text or ""
            if href:
                return href.strip()
    return ""


def parse_xml(raw: bytes, source: dict) -> list[dict]:
    root = ET.fromstring(raw)
    nodes = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() in {"item", "entry"}]
    items = []
    for node in nodes[: int(source.get("max_items", 10))]:
        title = child_text(node, ("title",))
        link = child_link(node)
        summary = child_text(node, ("description", "summary", "content"))
        published = child_text(node, ("pubdate", "published", "updated", "date"))
        if title or summary:
            items.append({"source": source["name"], "title": title or "Sem título", "summary": summary, "url": link if link.startswith("http") else source["url"], "published_at": published})
    return items


def parse_json(raw: bytes, source: dict) -> list[dict]:
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        values = payload["vulnerabilities"]
    elif isinstance(payload, list):
        values = payload
    else:
        values = []
    items = []
    for value in values[: int(source.get("max_items", 10))]:
        if not isinstance(value, dict):
            continue
        cve = value.get("cveMetadata") or {}
        container = value.get("containers") or {}
        cna = container.get("cna") or {}
        descriptions = cna.get("descriptions") or []
        description = next((d.get("value") for d in descriptions if isinstance(d, dict)), "")
        title = value.get("summary") or value.get("shortDescription") or cve.get("cveId") or value.get("ghsa_id") or "Advisory"
        url = value.get("html_url") or value.get("url") or source["url"]
        published = value.get("published_at") or value.get("dateAdded") or cve.get("datePublished") or value.get("updated_at") or ""
        vendor = value.get("vendorProject") or ""
        product = value.get("product") or ""
        severity = value.get("severity") or ""
        details = " ".join(part for part in (vendor, product, severity, description, value.get("notes", "")) if part)
        items.append({"source": source["name"], "title": clean_text(title), "summary": clean_text(details), "url": url if str(url).startswith("http") else source["url"], "published_at": clean_text(published)})
    return items


def fetch_sources() -> tuple[list[dict], list[str]]:
    sources = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    collected: list[dict] = []
    failures: list[str] = []
    for source in sources:
        request = urllib.request.Request(source["url"], headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/rss+xml, application/atom+xml, application/xml, text/xml"})
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(2_000_000)
            collected.extend(parse_xml(raw, source) if source.get("format") == "xml" else parse_json(raw, source))
        except (OSError, urllib.error.URLError, ET.ParseError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"{source['name']}: {type(exc).__name__}")
    return collected, failures


def build_prompt(items: list[dict], failures: list[str]) -> str:
    context = json.dumps(items, ensure_ascii=False, indent=2)[:45_000]
    failure_note = ", ".join(failures) if failures else "nenhuma"
    return f"""Você é um analista defensivo e mentor técnico para um estudante de ciência da computação que quer construir carreira e portfólio em cibersegurança.

Use somente os itens de fontes fornecidos abaixo. Não invente fatos, datas, CVEs, impacto ou links. Filtre agressivamente e mantenha no máximo 5 sinais recentes que tenham aplicação prática em estudos, projetos de portfólio, redes, Linux, cloud security, threat intelligence, vulnerabilidades, secure coding ou IA defensiva. Evite duplicatas, hype e conteúdo sem evidência.

Retorne SOMENTE JSON válido, sem markdown, comentários ou texto antes/depois. Mantenha cada campo textual curto e escape aspas internas corretamente. Não ultrapasse 5 sinais.

Formato obrigatório:
{{
  "coverage_window": "...", "executive_summary": "...", "signals": [{{"title": "...", "category": "...", "relevance": "alta|média", "confidence": "alta|média|baixa", "what_changed": "...", "why_it_matters": "...", "application": "...", "source_name": "...", "source_url": "https://...", "published_at": "..."}}],
  "experiment": {{"title": "...", "objective": "...", "prerequisites": ["..."], "steps": ["..."], "expected_evidence": ["..."], "stop_condition": "..."}},
  "discarded": "...", "backlog": ["..."]
}}

O experimento deve ser defensivo, autorizado e executável em 20–60 minutos em laboratório local, container, aplicação intencionalmente vulnerável ou dados sintéticos. Nunca recomende atacar sistemas reais.

Falhas de coleta: {failure_note}

Itens coletados:
{context}
"""


def parse_json_response(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", text, flags=re.IGNORECASE)
    candidates = [text]
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])
    last_error: json.JSONDecodeError | None = None
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(parsed, dict):
            return parsed
    if last_error:
        raise last_error
    raise ValueError("OpenRouter não retornou um objeto JSON")


def call_openrouter(prompt: str) -> dict:
    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY ausente")
    model = os.environ.get("OPENROUTER_MODEL", "openrouter/free").strip()
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 4000, "temperature": 0.1}).encode("utf-8")
    request = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "HTTP-Referer": "https://luisglauria.github.io/cybersecurity-second-brain/", "X-Title": "Cybersecurity Second Brain"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"OpenRouter API HTTP {exc.code}") from exc
    choices = payload.get("choices", [])
    message = choices[0].get("message", {}) if choices else {}
    text = message.get("content", "") if isinstance(message, dict) else ""
    if not text:
        raise ValueError("Resposta do OpenRouter sem texto")
    return parse_json_response(text)


def call_model(prompt: str) -> dict:
    return call_openrouter(prompt)


def normalise_report(report: dict, collected_count: int, failures: list[str]) -> dict:
    signals = []
    for signal in report.get("signals", [])[:7]:
        if not isinstance(signal, dict):
            continue
        url = str(signal.get("source_url", ""))
        if not url.startswith(("http://", "https://")):
            url = ""
        signals.append({"title": clean_text(signal.get("title"), 180), "category": clean_text(signal.get("category"), 80), "relevance": clean_text(signal.get("relevance"), 20), "confidence": clean_text(signal.get("confidence"), 20), "what_changed": clean_text(signal.get("what_changed"), 500), "why_it_matters": clean_text(signal.get("why_it_matters"), 500), "application": clean_text(signal.get("application"), 500), "source_name": clean_text(signal.get("source_name"), 120), "source_url": url, "published_at": clean_text(signal.get("published_at"), 80)})
    experiment = report.get("experiment") if isinstance(report.get("experiment"), dict) else {}
    return {"generated_at": now_local().isoformat(), "coverage_window": clean_text(report.get("coverage_window"), 180), "executive_summary": clean_text(report.get("executive_summary"), 700), "signals": signals, "experiment": {"title": clean_text(experiment.get("title"), 180), "objective": clean_text(experiment.get("objective"), 500), "prerequisites": [clean_text(x, 220) for x in experiment.get("prerequisites", [])[:6]], "steps": [clean_text(x, 300) for x in experiment.get("steps", [])[:8]], "expected_evidence": [clean_text(x, 240) for x in experiment.get("expected_evidence", [])[:6]], "stop_condition": clean_text(experiment.get("stop_condition"), 300)}, "discarded": clean_text(report.get("discarded"), 500), "backlog": [clean_text(x, 240) for x in report.get("backlog", [])[:3]], "collection": {"items": collected_count, "failures": failures}, "status": "ok"}


def local_fallback_report(items: list[dict]) -> dict:
    signals = []
    for item in items[:5]:
        signals.append({"title": item.get("title", "Sinal coletado"), "category": "triagem manual", "relevance": "média", "confidence": "baixa", "what_changed": item.get("summary", "Revisar a atualização na fonte original."), "why_it_matters": "O item foi coletado, mas precisa de leitura manual porque a resposta estruturada da IA não foi validada.", "application": "Ler a fonte original em ambiente autorizado e registrar uma conclusão técnica curta.", "source_name": item.get("source", "Fonte allowlist"), "source_url": item.get("url", ""), "published_at": item.get("published_at", "")})
    return {"coverage_window": "Triagem local após falha de formatação da IA", "executive_summary": "A coleta foi concluída, mas a resposta do roteador gratuito não passou na validação JSON. Os sinais foram mantidos para revisão manual.", "signals": signals, "experiment": {"title": "Validar uma fonte em laboratório", "objective": "Ler uma fonte coletada e registrar o impacto defensivo sem interagir com sistemas reais.", "prerequisites": ["Fonte original acessível", "Ambiente de anotações", "Escopo autorizado"], "steps": ["Escolher um sinal", "Confirmar a informação na fonte original", "Registrar impacto, mitigação e dúvida restante"], "expected_evidence": ["Nota técnica com fonte", "Escopo de validação documentado"], "stop_condition": "Parar se a atividade exigir acesso a um ativo não autorizado."}, "discarded": "Síntese automática indisponível; nenhum fato adicional foi inventado.", "backlog": ["Revisar os sinais manualmente", "Executar novamente no próximo ciclo", "Manter o escopo defensivo"]}


def esc(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def bullets(values: list[str]) -> str:
    return "".join(f"<li>{esc(value)}</li>" for value in values) or "<li>Não informado.</li>"


def render(report: dict, failure: str | None = None) -> str:
    warning = ""
    if failure:
        warning = f'<div class="alert" role="alert"><strong>Última execução com falha:</strong> {esc(failure)}. O relatório abaixo é uma triagem local ou o último resultado válido.</div>'
    signal_cards = []
    for signal in report.get("signals", []):
        source = ""
        if signal.get("source_url"):
            source = f'<a href="{esc(signal["source_url"])}" target="_blank" rel="noopener noreferrer">Fonte direta</a>'
        signal_cards.append(f"""<article class="card signal"><div class="meta">{esc(signal.get('category'))} · relevância {esc(signal.get('relevance'))} · confiança {esc(signal.get('confidence'))}</div><h3>{esc(signal.get('title'))}</h3><p><strong>O que mudou:</strong> {esc(signal.get('what_changed'))}</p><p><strong>Por que importa:</strong> {esc(signal.get('why_it_matters'))}</p><p><strong>Aplicação:</strong> {esc(signal.get('application'))}</p><p class="source">{esc(signal.get('source_name'))} · {esc(signal.get('published_at'))} · {source}</p></article>""")
    experiment = report.get("experiment", {})
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Briefing diário de cibersegurança filtrado para estudos e portfólio."><title>Briefing diário de cibersegurança</title><style>:root{{--bg:#0b1020;--panel:#121a2d;--text:#e8eefc;--muted:#a8b4ce;--accent:#63e6be;--blue:#74c0fc;--border:#2b3a5e;--warn:#ffd166}}*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#0b1020,#111a31);color:var(--text);font:16px/1.6 system-ui,sans-serif}}main{{width:min(1120px,calc(100% - 32px));margin:auto;padding:38px 0 64px}}h1,h2,h3{{line-height:1.2}}h1{{font-size:clamp(2rem,5vw,3.5rem)}}.card,.summary{{background:rgba(18,26,45,.94);border:1px solid var(--border);border-radius:16px;padding:20px;margin-top:16px}}.signals{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}}.eyebrow{{color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.12em;font-size:.78rem}}.timestamp,.meta,.source,li,footer{{color:var(--muted)}}.alert{{border-left:4px solid var(--warn);background:#3c3014;padding:14px 18px;border-radius:10px;margin:18px 0}}a{{color:var(--blue)}}footer{{margin-top:38px;border-top:1px solid var(--border);padding-top:16px;font-size:.88rem}}</style></head><body><main><header><div><div class="eyebrow">Cybersecurity Second Brain</div><h1>Briefing diário de cibersegurança</h1><p>Novidades filtradas para aprendizado aplicado e projetos de portfólio.</p></div><div class="timestamp">Gerado em {esc(report.get('generated_at'))}</div></header>{warning}<section class="summary"><h2>Síntese executiva</h2><p>{esc(report.get('executive_summary')) or 'Nenhuma síntese disponível.'}</p><p class="meta">Janela: {esc(report.get('coverage_window'))} · Itens coletados: {esc(report.get('collection', {}).get('items'))}</p></section><section><h2>Sinais selecionados</h2><div class="signals">{''.join(signal_cards) or '<div class="card"><p>Nenhum sinal passou pelo filtro.</p></div>'}</div></section><section class="card"><h2>Experimento recomendado</h2><h3>{esc(experiment.get('title')) or 'Nenhum experimento definido'}</h3><p><strong>Objetivo:</strong> {esc(experiment.get('objective'))}</p><h3>Pré-requisitos</h3><ul>{bullets(experiment.get('prerequisites', []))}</ul><h3>Passos</h3><ol>{bullets(experiment.get('steps', []))}</ol><h3>Evidências esperadas</h3><ul>{bullets(experiment.get('expected_evidence', []))}</ul><p><strong>Condição de parada:</strong> {esc(experiment.get('stop_condition'))}</p></section><section class="card"><h2>Triagem</h2><p><strong>Descartados:</strong> {esc(report.get('discarded')) or 'Sem observações.'}</p><h3>Backlog</h3><ul>{bullets(report.get('backlog', []))}</ul></section><footer>Uso educacional e defensivo. Execute testes somente em ativos autorizados, laboratórios locais ou dados sintéticos.</footer></main></body></html>"""


def default_report() -> dict:
    return {"generated_at": now_local().isoformat(), "coverage_window": "", "executive_summary": "Ainda não há um briefing válido.", "signals": [], "experiment": {}, "discarded": "", "backlog": [], "collection": {"items": 0, "failures": []}, "status": "empty"}


def main() -> int:
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    previous = default_report()
    if STATE_PATH.exists():
        try:
            previous = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    failure: str | None = None
    items: list[dict] = []
    failures: list[str] = []
    try:
        items, failures = fetch_sources()
        if not items:
            raise RuntimeError("nenhuma fonte retornou itens")
        report = normalise_report(call_model(build_prompt(items, failures)), len(items), failures)
        STATE_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        failure = f"{type(exc).__name__}: {str(exc)[:240]}"
        if items:
            report = normalise_report(local_fallback_report(items), len(items), failures)
            report["last_failure_at"] = now_local().isoformat()
            report["last_failure"] = failure
            STATE_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        else:
            report = previous
            report["last_failure_at"] = now_local().isoformat()
            report["last_failure"] = failure
        print(f"::warning::{failure}")
    INDEX_PATH.write_text(render(report, failure), encoding="utf-8")
    print(f"Generated {INDEX_PATH} with status={report.get('status', 'unknown')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
