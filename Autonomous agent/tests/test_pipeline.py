import os
import pytest
from pathlib import Path
from src.config import Config
from src.persistence.database import CyberGuardDB
from run_pipeline import main as run_main

def test_end_to_end_pipeline():
    # Remove existing SQLite artifacts for a clean test
    sqlite_db = Config.SQLITE_PATH
    if sqlite_db.exists():
        try:
            sqlite_db.unlink()
        except Exception:
            pass

    # Clear old playbooks
    if Config.PLAYBOOK_DIR.exists():
        for f in Config.PLAYBOOK_DIR.glob("playbook_*.md"):
            try:
                f.unlink()
            except Exception:
                pass

    # Execute main runner
    run_main()

    # 1. At least one persistence backend must have events
    db = CyberGuardDB()
    events = db.get_events(limit=10)
    # If ES is primary, get_events queries ES; if SQLite fallback, queries db file
    # Either way events > 0 means the pipeline wrote data successfully
    assert len(events) > 0, "No events found in any persistence backend after pipeline run"

    # 2. Playbook markdown files should be created on disk
    playbook_files = list(Config.PLAYBOOK_DIR.glob("playbook_*.md"))
    assert len(playbook_files) > 0, "No playbook files generated"

    # 3. Playbook content must contain key compliance sections
    with open(playbook_files[0], "r", encoding="utf-8") as f:
        content = f.read()
    assert "Regulatory Compliance" in content, "Playbook missing Regulatory Compliance section"
    assert len(content) > 200, "Playbook content too short"

    db.close()
