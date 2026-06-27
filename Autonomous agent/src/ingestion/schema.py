from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid

class CanonicalEvent(BaseModel):
    event_id: str = Field(default=None)
    timestamp: str = Field(...)  # ISO 8601 string
    log_source: str = Field(...)  # 'windows_event', 'ssh', 'proxy', 'firewall', etc.
    severity: str = Field(default="INFO")  # 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    action_type: str = Field(...)  # 'login_attempt', 'process_spawn', 'network_connect', 'file_modification'
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    bytes_transferred: float = Field(default=0.0)
    status: Optional[str] = None  # 'success', 'failure'
    raw_log: str = Field(...)  # The original unparsed record for forensic auditing

    def __init__(self, **data):
        if "event_id" not in data or not data["event_id"]:
            data["event_id"] = str(uuid.uuid4())
        super().__init__(**data)

    def to_dict(self):
        return self.dict()
