"""Daily cybersecurity briefing generator for GitHub Actions."""
from __future__ import annotations

import datetime as dt
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "sources.json"
SITE = ROOT / "site"
STATE = SITE / "briefing.json"
INDEX = SITE / "index.html"
TZ = ZoneInfo("America/Sao_Paulo")
UA = "cybersecurity-second-brain/1.0"


def clean(value, limit=700):
    text = html.unescape(str(value or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def xml_items(raw, source):
    root = ET.fromstring(raw)
    nodes = [n for n in root.iter() if n.tag.rsplit("}", 1)[-1].lower() in {"item", "entry"}]
    result = []
    for node in nodes[:int(source.get("max_items", 10))]:
        fields = {}
        for child in list(node):
            tag = child.tag.rsplit("}", 1)[-1].lower()
            if tag == "link":
                fields["url"] = child.attrib.get("href") or child.text or ""
            elif tag in {"title", "description", "summary", "content", "published", "updated", "pubdate"}:
                fields.setdefault(tag, clean(child.text))
        if fields.get("title") or fields.get("summary") or fields.get("description"):
            result.append({"source": source["name"], "title": fields.get("title", "Sem título"), "summary": fields.get("summary") or fields.get("description") or fields.get("content", ""), "url": fields.get("url", source["url"]), "published_at": fields.get("published") or fields.get("updated") or fields.get("pubdate", "")})
    return result


def json_items(raw, source):
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    values = payload.get("vulnerabilities", []) if isinstance(payload, dict) else payload
    result = []
    for value in values[:int(source.get("max_items", 10))] if isinstance(values, list) else []:
        if not isinstance(value, dict):
            continue
        cve = value.get("cveMetadata") or {}
        cna = ((value.get("containers") or {}).get("cna") or {})
        descriptions = cna.get("descriptions") or []
        description = next((d.get("value", "") for d in descriptions if isinstance(d, dict)), "")
        title = value.get("summary") or value.get("shortDescription") or cve.get("cveId") or value.get("ghsa_id") or "Advisory"
        url = value.get("html_url") or value.get("url") or source["url"]
        result.append({"source": source["name"], "title": clean(title, 180), "summary": clean(" ".join(str(x) for x in [value.get("vendorProject", ""), value.get("product", ""), value.get("severity", ""), description] if x)), "url": url if str(url).startswith("http") else source["url"], "published_at": clean(value.get("published_at") or value.get("dateAdded") or cve.get("datePublished") or value.get("updated_at", ""), 80)})
    return result


def collect():
    items, failures = [], []
    for source in json.loads(CONFIG.read_text(encoding="utf-8")):
        request = urllib.request.Request(source["url"], headers={"User-Agent": UA, "Accept": "application/json, application/xml, application/rss+xml, application/atom+xml"})
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(2_000_000)
            items.extend(xml_items(raw, source) if source.get("format") == "xml" else json_items(raw, source))
        except (OSError, urllib.error.URLError, ET.ParseError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"{source['name']}: {type(exc).__name__}")
    return items, failures


def make_prompt(items, failures):
    return """Você é um analista defensivo e mentor técnico para um estudante de computação interessado em cibersegurança. Use somente os itens fornecidos; não invente fatos, datas, CVEs, impactos ou links. Selecione no máximo 7 sinais práticos para estudos, Linux, redes, cloud security, threat intelligence, vulnerabilidades, secure coding ou IA defensiva. Retorne somente JSON válido neste formato: {\"coverage_window\":\"...\",\"executive_summary\":\"...\",\"signals\":[{\"title\":\"...\",\"category\":\"...\",\"relevance\":\"alta|média\",\"confidence\":\"alta|média|baixa\",\"what_changed\":\"...\",\"why_it_matters\":\"...\",\"application\":\"...\",\"source_name\":\"...\",\"source_url\":\"https://...\",\"published_at\":\"...\"}],\"experiment\":{\"title\":\"...\",\"objective\":\"...\",\"prerequisites\":[\"...\"],\"steps\":[\"...\"],\"expected_evidence\":[\"...\"],\"stop_condition\":\"...\"},\"discarded\":\"...\",\"backlog\":[\"...\"]}. O experimento deve ser autorizado, defensivo e executável em 20–60 minutos em laboratório local, container, aplicação intencionalmente vulnerável ou dados sintéticos. Nunca recomende atacar sistemas reais. Falhas de coleta: """ + (", ".join(failures) or "nenhuma") + "\nItens coletados:\n" + json.dumps(items, ensure_ascii=False)[:45000]


def ask_gemini(prompt):
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise RuntimeError("GEMINI_API_KEY ausente")
    model = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite").strip()
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": 3500, "responseMimeType": "application/json"}}).encode()
    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/" + urllib.parse.quote(model, safe="") + ":generateContent"
    request = urllib.request.Request(endpoint, data=body, headers={"x-goog-api-key": key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Gemini API HTTP {exc.code}") from exc
    parts = (payload.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
    text = next((part.get("text", "") for part in parts if isinstance(part, dict)), "").strip()
    text = re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", text, flags=re.I)
    if not text:
        raise RuntimeError("Gemini não retornou texto")
    return json.loads(text)


def normalize(report, count, failures):
    signals = []
    for item in report.get("signals", [])[:7]:
        if isinstance(item, dict):
            url = str(item.get("source_url", ""))
            signals.append({"title": clean(item.get("title"), 180), "category": clean(item.get("category"), 80), "relevance": clean(item.get("relevance"), 20), "confidence": clean(item.get("confidence"), 20), "what_changed": clean(item.get("what_changed"), 500), "why_it_matters": clean(item.get("why_it_matters"), 500), "application": clean(item.get("application"), 500), "source_name": clean(item.get("source_name"), 120), "source_url": url if url.startswith(("http://", "https://")) else "", "published_at": clean(item.get("published_at"), 80)})
    experiment = report.get("experiment") if isinstance(report.get("experiment"), dict) else {}
    return {"generated_at": dt.datetime.now(TZ).replace(microsecond=0).isoformat(), "coverage_window": clean(report.get("coverage_window"), 180), "executive_summary": clean(report.get("executive_summary"), 700), "signals": signals, "experiment": {"title": clean(experiment.get("title"), 180), "objective": clean(experiment.get("objective"), 500), "prerequisites": [clean(x, 220) for x in experiment.get("prerequisites", [])[:6]], "steps": [clean(x, 300) for x in experiment.get("steps", [])[:8]], "expected_evidence": [clean(x, 240) for x in experiment.get("expected_evidence", [])[:6]], "stop_condition": clean(experiment.get("stop_condition"), 300)}, "discarded": clean(report.get("discarded"), 500), "backlog": [clean(x, 240) for x in report.get("backlog", [])[:3]], "collection": {"items": count, "failures": failures}, "status": "ok"}


def esc(value):
    return html.escape(str(value or ""), quote=True)


def list_html(values, tag="ul"):
    return f"<{tag}>" + "".join(f"<li>{esc(value)}</li>" for value in values) + f"</{tag}>" if values else "<p>Não informado.</p>"


def render(report, failure=""):
    warning = f"<div class='alert'><strong>Falha na última execução:</strong> {esc(failure)}. Exibindo o último resultado válido.</div>" if failure else ""
    cards = []
    for item in report.get("signals", []):
        source = f"<a href='{esc(item.get('source_url'))}' target='_blank' rel='noopener'>Fonte direta</a>" if item.get("source_url") else ""
        cards.append(f"<article class='card'><small>{esc(item.get('category'))} · relevância {esc(item.get('relevance'))} · confiança {esc(item.get('confidence'))}</small><h3>{esc(item.get('title'))}</h3><p><b>O que mudou:</b> {esc(item.get('what_changed'))}</p><p><b>Por que importa:</b> {esc(item.get('why_it_matters'))}</p><p><b>Aplicação:</b> {esc(item.get('application'))}</p><small>{esc(item.get('source_name'))} · {esc(item.get('published_at'))} · {source}</small></article>")
    experiment = report.get("experiment", {})
    return f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Briefing diário de cibersegurança</title><style>body{{margin:0;background:#0b1020;color:#e8eefc;font:16px/1.6 system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:32px 16px}}.card{{background:#121a2d;border:1px solid #2b3a5e;border-radius:14px;padding:18px;margin:14px 0}}.signals{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}}small{{color:#a8b4ce}}a{{color:#74c0fc}}.alert{{border-left:4px solid #ffd166;background:#3c3014;padding:12px}}</style></head><body><main><p><b>CYBERSECURITY SECOND BRAIN</b></p><h1>Briefing diário de cibersegurança</h1><p>Gerado em {esc(report.get('generated_at'))}</p>{warning}<section class='card'><h2>Síntese executiva</h2><p>{esc(report.get('executive_summary')) or 'Nenhuma síntese disponível.'}</p><small>Janela: {esc(report.get('coverage_window'))} · Itens coletados: {esc(report.get('collection', {}).get('items'))}</small></section><h2>Sinais selecionados</h2><div class='signals'>{''.join(cards) or '<article class="card">Nenhum sinal passou pelo filtro.</article>'}</div><section class='card'><h2>Experimento recomendado</h2><h3>{esc(experiment.get('title'))}</h3><p>{esc(experiment.get('objective'))}</p><h3>Pré-requisitos</h3>{list_html(experiment.get('prerequisites', []))}<h3>Passos</h3>{list_html(experiment.get('steps', []), 'ol')}<h3>Evidências esperadas</h3>{list_html(experiment.get('expected_evidence', []))}<p><b>Condição de parada:</b> {esc(experiment.get('stop_condition'))}</p></section><section class='card'><h2>Triagem</h2><p>{esc(report.get('discarded'))}</p><h3>Backlog</h3>{list_html(report.get('backlog', []))}</section><footer>Uso educacional e defensivo. Teste somente em ativos autorizados, laboratórios locais ou dados sintéticos.</footer></main></body></html>"


def main():
    SITE.mkdir(parents=True, exist_ok=True)
    previous = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {"generated_at": "", "coverage_window": "", "executive_summary": "Ainda não há briefing válido.", "signals": [], "experiment": {}, "discarded": "", "backlog": [], "collection": {"items": 0, "failures": []}, "status": "empty"}
    failure = ""
    try:
        items, failures = collect()
        if not items:
            raise RuntimeError("nenhuma fonte retornou itens")
        report = normalize(ask_gemini(make_prompt(items, failures)), len(items), failures)
        STATE.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        failure = f"{type(exc).__name__}: {str(exc)[:240]}"
        report = previous
        report["last_failure"] = failure
        report["last_failure_at"] = dt.datetime.now(TZ).replace(microsecond=0).isoformat()
        print(f"::warning::{failure}")
    INDEX.write_text(render(report, failure), encoding="utf-8")
    print(f"Generated {INDEX} with status={report.get('status', 'unknown')}")


if __name__ == "__main__":
    sys.exit(main())
