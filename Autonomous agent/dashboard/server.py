"""
CyberGuard-IR Analyst Dashboard — FastAPI Backend
Serves the dashboard UI and exposes REST endpoints backed by Elasticsearch (SQLite fallback).
"""
import json
import sqlite3
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from src.config import Config
from src.utils.logging import get_logger

logger = get_logger("dashboard")

app = FastAPI(title="CyberGuard-IR Dashboard", version="1.0.0")

# ── Database helpers ──────────────────────────────────────────────────────────

def _get_es_client():
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(Config.ELASTICSEARCH_URL, request_timeout=10)
        if es.ping():
            return es
    except Exception:
        pass
    return None


def get_incidents() -> List[Dict[str, Any]]:
    es = _get_es_client()
    if es:
        try:
            res = es.search(
                index="cg-incidents",
                body={"query": {"match_all": {}}, "size": 100,
                      "sort": [{"cfr_score": {"order": "desc"}}]}
            )
            return [h["_source"] for h in res["hits"]["hits"]]
        except Exception as e:
            logger.error("ES incidents query failed", error=str(e))

    # SQLite fallback
    db_path = Config.SQLITE_PATH
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents ORDER BY cfr_score DESC")
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["entities"] = json.loads(d.get("entities", "[]"))
        except Exception:
            d["entities"] = []
        try:
            details = json.loads(d.get("details", "{}"))
            d.update(details)
        except Exception:
            pass
        results.append(d)
    return results


def get_playbook(incident_id: str) -> Optional[Dict[str, Any]]:
    es = _get_es_client()
    if es:
        try:
            res = es.search(
                index="cg-playbooks",
                body={"query": {"term": {"incident_id.keyword": incident_id}}, "size": 1}
            )
            hits = res["hits"]["hits"]
            if hits:
                return hits[0]["_source"]
        except Exception as e:
            logger.error("ES playbook query failed", error=str(e))

    # SQLite fallback
    db_path = Config.SQLITE_PATH
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM playbooks WHERE incident_id = ? LIMIT 1", (incident_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        d = dict(row)
        try:
            d["mitigation_actions"] = json.loads(d.get("mitigation_actions", "[]"))
        except Exception:
            d["mitigation_actions"] = []
        return d
    return None


def get_stats() -> Dict[str, Any]:
    incidents = get_incidents()
    total = len(incidents)
    avg_cfr = round(sum(i.get("cfr_score", 0) for i in incidents) / total, 2) if total else 0
    stages = {}
    for inc in incidents:
        stage = inc.get("highest_mitre_stage", "Unknown")
        stages[stage] = stages.get(stage, 0) + 1

    # Event count
    es = _get_es_client()
    event_count = 0
    if es:
        try:
            res = es.count(index="cg-events")
            event_count = res["count"]
        except Exception:
            pass
    else:
        db_path = Config.SQLITE_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events")
            event_count = cur.fetchone()[0]
            conn.close()

    return {
        "total_incidents": total,
        "avg_cfr_score": avg_cfr,
        "total_events": event_count,
        "mitre_stage_counts": stages,
        "persistence_backend": "Elasticsearch" if es else "SQLite"
    }


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def api_stats():
    return get_stats()


@app.get("/api/incidents")
def api_incidents():
    return get_incidents()


@app.get("/api/incidents/{incident_id}/playbook")
def api_playbook(incident_id: str):
    pb = get_playbook(incident_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


# ── Serve Dashboard HTML ───────────────────────────────────────────────────────

DASHBOARD_HTML = Path(__file__).parent / "index.html"

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    if not DASHBOARD_HTML.exists():
        return HTMLResponse("<h1>Dashboard HTML not found</h1>", status_code=500)
    return HTMLResponse(DASHBOARD_HTML.read_text(encoding="utf-8"))


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  CyberGuard-IR Analyst Dashboard")
    print("  http://localhost:8080")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
