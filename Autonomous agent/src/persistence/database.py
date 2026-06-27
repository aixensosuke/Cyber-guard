import json
import sqlite3
from typing import List, Dict, Any, Optional
from elasticsearch import Elasticsearch
from src.config import Config
from src.ingestion.schema import CanonicalEvent
from src.utils.logging import get_logger

logger = get_logger("database")

class CyberGuardDB:
    def __init__(self):
        self.use_es = False
        self.es_client: Optional[Elasticsearch] = None
        self.sqlite_conn: Optional[sqlite3.Connection] = None
        
        # Try establishing Elasticsearch connection
        try:
            self.es_client = Elasticsearch(
                Config.ELASTICSEARCH_URL,
                max_retries=2,
                request_timeout=30
            )
            if self.es_client.ping():
                self.use_es = True
                logger.info("Connected to Elasticsearch", url=Config.ELASTICSEARCH_URL)
            else:
                logger.warn("Elasticsearch ping failed. Falling back to SQLite.")
        except Exception as e:
            logger.warn("Failed to connect to Elasticsearch. Falling back to SQLite.", error=str(e))

        if not self.use_es:
            self._init_sqlite()

    def _init_sqlite(self):
        logger.info("Initializing SQLite database", path=str(Config.SQLITE_PATH))
        self.sqlite_conn = sqlite3.connect(Config.SQLITE_PATH, check_same_thread=False)
        cursor = self.sqlite_conn.cursor()
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                log_source TEXT,
                severity TEXT,
                username TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                destination_port INTEGER,
                action_type TEXT,
                process_name TEXT,
                command_line TEXT,
                file_path TEXT,
                bytes_transferred REAL,
                status TEXT,
                raw_log TEXT
            )
        """)

        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                timestamp TEXT,
                entities TEXT,        -- JSON array of entities involved
                cfr_score REAL,
                mitre_stage TEXT,
                details TEXT          -- JSON string of audit/CFR breakdown
            )
        """)

        # Playbooks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS playbooks (
                playbook_id TEXT PRIMARY KEY,
                incident_id TEXT,
                timestamp TEXT,
                mitigation_actions TEXT, -- JSON array of containment actions
                playbook_content TEXT,   -- Markdown text
                model_reasoning TEXT,    -- LLM thought process
                analyst_approved INTEGER DEFAULT 0,
                analyst_notes TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        """)
        
        self.sqlite_conn.commit()

    def initialize_storage(self):
        if self.use_es:
            # Create ES Indices
            indices = ["cg-events", "cg-incidents", "cg-playbooks"]
            for idx in indices:
                try:
                    if not self.es_client.indices.exists(index=idx):
                        self.es_client.indices.create(index=idx)
                        logger.info("Created Elasticsearch index", index=idx)
                except Exception as e:
                    logger.error("Failed to create index in ES", index=idx, error=str(e))
        else:
            # SQLite tables are created in _init_sqlite()
            pass

    def save_event(self, event: CanonicalEvent) -> bool:
        return self.save_events([event])

    def save_events(self, events: List[CanonicalEvent]) -> bool:
        if not events:
            return True
            
        if self.use_es:
            try:
                operations = []
                for event in events:
                    operations.append({"index": {"_index": "cg-events", "_id": event.event_id}})
                    operations.append(event.to_dict())
                self.es_client.bulk(operations=operations)
                logger.info("Saved events to Elasticsearch", count=len(events))
                return True
            except Exception as e:
                logger.error("Failed to bulk save to Elasticsearch", error=str(e))
                return False
        else:
            try:
                cursor = self.sqlite_conn.cursor()
                data = [
                    (
                        e.event_id, e.timestamp, e.log_source, e.severity, e.username,
                        e.source_ip, e.destination_ip, e.destination_port, e.action_type,
                        e.process_name, e.command_line, e.file_path, e.bytes_transferred,
                        e.status, e.raw_log
                    )
                    for e in events
                ]
                cursor.executemany("""
                    INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                self.sqlite_conn.commit()
                logger.info("Saved events to SQLite", count=len(events))
                return True
            except Exception as e:
                logger.error("Failed to save events to SQLite", error=str(e))
                return False

    def get_events(self, limit: int = 1000) -> List[Dict[str, Any]]:
        if self.use_es:
            try:
                res = self.es_client.search(
                    index="cg-events",
                    body={"query": {"match_all": {}}, "size": limit, "sort": [{"timestamp": "asc"}]}
                )
                return [hit["_source"] for hit in res["hits"]["hits"]]
            except Exception as e:
                logger.error("Failed to retrieve events from ES", error=str(e))
                return []
        else:
            try:
                self.sqlite_conn.row_factory = sqlite3.Row
                cursor = self.sqlite_conn.cursor()
                cursor.execute("SELECT * FROM events ORDER BY timestamp ASC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                # Reset row factory
                self.sqlite_conn.row_factory = None
                return [dict(r) for r in rows]
            except Exception as e:
                logger.error("Failed to query events from SQLite", error=str(e))
                return []

    def save_incident(self, incident: Dict[str, Any]) -> bool:
        incident_id = incident["incident_id"]
        if self.use_es:
            try:
                self.es_client.index(index="cg-incidents", id=incident_id, document=incident)
                logger.info("Saved Incident to Elasticsearch", incident_id=incident_id)
                return True
            except Exception as e:
                logger.error("Failed to save incident to ES", incident_id=incident_id, error=str(e))
                return False
        else:
            try:
                cursor = self.sqlite_conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    incident_id,
                    incident.get("timestamp"),
                    json.dumps(incident.get("entities", [])),
                    incident.get("cfr_score", 0.0),
                    incident.get("mitre_stage", "Unknown"),
                    json.dumps(incident)
                ))
                self.sqlite_conn.commit()
                logger.info("Saved Incident to SQLite", incident_id=incident_id)
                return True
            except Exception as e:
                logger.error("Failed to save incident to SQLite", incident_id=incident_id, error=str(e))
                return False

    def save_playbook(self, playbook: Dict[str, Any]) -> bool:
        playbook_id = playbook["playbook_id"]
        if self.use_es:
            try:
                self.es_client.index(index="cg-playbooks", id=playbook_id, document=playbook)
                logger.info("Saved Playbook to Elasticsearch", playbook_id=playbook_id)
                return True
            except Exception as e:
                logger.error("Failed to save playbook to ES", playbook_id=playbook_id, error=str(e))
                return False
        else:
            try:
                cursor = self.sqlite_conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO playbooks VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    playbook_id,
                    playbook.get("incident_id"),
                    playbook.get("timestamp"),
                    json.dumps(playbook.get("mitigation_actions", [])),
                    playbook.get("playbook_content"),
                    playbook.get("model_reasoning"),
                    1 if playbook.get("analyst_approved", False) else 0,
                    playbook.get("analyst_notes", "")
                ))
                self.sqlite_conn.commit()
                logger.info("Saved Playbook to SQLite", playbook_id=playbook_id)
                return True
            except Exception as e:
                logger.error("Failed to save playbook to SQLite", playbook_id=playbook_id, error=str(e))
                return False
                
    def close(self):
        if self.sqlite_conn:
            self.sqlite_conn.close()
            logger.info("SQLite database connection closed")
