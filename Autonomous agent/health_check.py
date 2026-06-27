"""CyberGuard-IR System Health Check"""
import sys, os, json, glob
sys.path.insert(0, 'd:/Autonomous agent')

results = {}

# 1. Elasticsearch
try:
    from elasticsearch import Elasticsearch
    es = Elasticsearch('http://localhost:9200', request_timeout=5)
    if es.ping():
        inc = es.count(index='cg-incidents')['count']
        pb  = es.count(index='cg-playbooks')['count']
        ev  = es.count(index='cg-events')['count']
        inc_ids = {h['_id'] for h in es.search(index='cg-incidents', body={"query":{"match_all":{}},"size":20})['hits']['hits']}
        pb_ids  = {h['_source']['incident_id'] for h in es.search(index='cg-playbooks', body={"query":{"match_all":{}},"size":20})['hits']['hits']}
        orphans = inc_ids - pb_ids
        results['elasticsearch'] = ('OK', f'incidents={inc}, playbooks={pb}, events={ev}, orphans={len(orphans)}')
    else:
        results['elasticsearch'] = ('FAIL', 'ping returned False')
except Exception as e:
    results['elasticsearch'] = ('FAIL', str(e))

# 2. Ollama
try:
    import urllib.request
    r = urllib.request.urlopen('http://localhost:11434/api/tags', timeout=5)
    data = json.loads(r.read())
    models = [m['name'] for m in data.get('models', [])]
    results['ollama'] = ('OK', f'models={models}')
except Exception as e:
    results['ollama'] = ('FAIL', str(e))

# 3. SQLite fallback DB
try:
    import sqlite3
    db = 'd:/Autonomous agent/cyberguard.db'
    if os.path.exists(db):
        conn = sqlite3.connect(db)
        cur  = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM events');    ev  = cur.fetchone()[0]
        cur.execute('SELECT COUNT(*) FROM incidents'); inc = cur.fetchone()[0]
        cur.execute('SELECT COUNT(*) FROM playbooks'); pb  = cur.fetchone()[0]
        conn.close()
        results['sqlite'] = ('OK', f'events={ev}, incidents={inc}, playbooks={pb}')
    else:
        results['sqlite'] = ('WARN', 'DB file not found (normal if ES is primary)')
except Exception as e:
    results['sqlite'] = ('FAIL', str(e))

# 4. Playbook markdown files
try:
    files = glob.glob('d:/Autonomous agent/playbooks/*.md')
    results['playbooks_dir'] = ('OK', f'{len(files)} markdown files on disk')
except Exception as e:
    results['playbooks_dir'] = ('FAIL', str(e))

# 5. Dashboard API
try:
    r    = urllib.request.urlopen('http://localhost:8080/api/stats', timeout=5)
    data = json.loads(r.read())
    results['dashboard_api'] = ('OK', f'incidents={data["total_incidents"]}, backend={data["persistence_backend"]}')
except Exception as e:
    results['dashboard_api'] = ('FAIL', str(e))

# 6. Core module imports
try:
    from src.ingestion.normalizer  import LogNormalizer
    from src.detection.detector    import CyberGuardDetector
    from src.ueba.analytics        import UEBAEngine
    from src.correlation.graph     import ThreatCorrelator
    from src.correlation.CFR       import CFRCalculator
    from src.orchestration.llm     import LocalLLMClient
    from src.orchestration.agent   import CyberGuardOrchestrator
    from src.persistence.database  import CyberGuardDB
    results['core_imports'] = ('OK', 'all 8 modules import cleanly')
except Exception as e:
    results['core_imports'] = ('FAIL', str(e))

# 7. Audit log
try:
    log = 'd:/Autonomous agent/cyberguard.audit.log'
    if os.path.exists(log):
        size = os.path.getsize(log)
        with open(log) as f:
            lines = sum(1 for _ in f)
        results['audit_log'] = ('OK', f'{lines} entries, {round(size/1024,1)} KB')
    else:
        results['audit_log'] = ('WARN', 'audit log file not found')
except Exception as e:
    results['audit_log'] = ('FAIL', str(e))

# -- Print report ----------------------------------------------------------
icons = {'OK': '[OK]  ', 'WARN': '[WARN]', 'FAIL': '[FAIL]'}
print()
print('=' * 65)
print('   CYBERGUARD-IR SYSTEM HEALTH CHECK')
print('=' * 65)
all_ok = True
for name, (status, detail) in results.items():
    icon = icons.get(status, '[???] ')
    if status == 'FAIL':
        all_ok = False
    print(f'  {icon}  {name:<20}  {detail}')
print('=' * 65)
print('  >> All systems operational' if all_ok else '  >> Some components need attention')
print('=' * 65)
print()
