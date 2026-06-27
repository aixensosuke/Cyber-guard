import hashlib
from typing import Dict, Any, List, Optional
import json
from datetime import datetime, timedelta
from src.ingestion.schema import CanonicalEvent
from src.utils.logging import get_logger

logger = get_logger("normalizer")

class LogNormalizer:
    def __init__(self, deduplication_window_seconds: int = 60):
        # Cache for deduplication: maps event signature hash to expiry datetime
        self.dedup_cache: Dict[str, datetime] = {}
        self.window = timedelta(seconds=deduplication_window_seconds)

    def _generate_signature(self, raw_log: Dict[str, Any]) -> str:
        # Generate a unique hash for signature-based deduplication
        # Use key fields: source, timestamp, user, ip, process/file, action
        keys = [
            str(raw_log.get("timestamp", "")),
            str(raw_log.get("log_source", raw_log.get("source", ""))),
            str(raw_log.get("username", raw_log.get("user", ""))),
            str(raw_log.get("source_ip", raw_log.get("src_ip", ""))),
            str(raw_log.get("action_type", raw_log.get("event_type", ""))),
            str(raw_log.get("command_line", raw_log.get("cmd", "")))
        ]
        sig_string = "|".join(keys)
        return hashlib.sha256(sig_string.encode("utf-8")).hexdigest()

    def _cleanup_cache(self, now: datetime):
        # Remove expired cache entries to prevent memory growth
        expired = [k for k, expiry in self.dedup_cache.items() if now > expiry]
        for k in expired:
            del self.dedup_cache[k]

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[CanonicalEvent]:
        now = datetime.utcnow()
        self._cleanup_cache(now)

        # 1. Deduplication Check
        sig = self._generate_signature(raw_log)
        if sig in self.dedup_cache:
            # Event is a duplicate within the sliding window
            logger.debug("Deduplicated event", signature=sig)
            return None
        
        # Add to cache with expiry
        self.dedup_cache[sig] = now + self.window

        try:
            # 2. Field mapping & normalization
            log_source = raw_log.get("log_source", raw_log.get("source", "unknown"))
            severity = raw_log.get("severity", "INFO").upper()
            
            # Extract timestamp or default to ISO now
            timestamp_raw = raw_log.get("timestamp")
            if timestamp_raw:
                try:
                    # Validate timestamp format or parse it
                    if isinstance(timestamp_raw, str):
                        dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
                    elif isinstance(timestamp_raw, (int, float)):
                        dt = datetime.utcfromtimestamp(timestamp_raw)
                    else:
                        dt = datetime.utcnow()
                except Exception:
                    dt = datetime.utcnow()
            else:
                dt = datetime.utcnow()
            
            timestamp = dt.isoformat()

            # Map vendor-specific fields to canonical ones
            username = raw_log.get("username") or raw_log.get("user") or raw_log.get("ActorUsername")
            source_ip = raw_log.get("source_ip") or raw_log.get("src_ip") or raw_log.get("IpAddress")
            destination_ip = raw_log.get("destination_ip") or raw_log.get("dest_ip") or raw_log.get("DestinationIp")
            
            dest_port = raw_log.get("destination_port") or raw_log.get("dest_port") or raw_log.get("DestinationPort")
            destination_port = int(dest_port) if dest_port is not None else None

            action_type = raw_log.get("action_type") or raw_log.get("event_type") or raw_log.get("Activity") or "unknown"
            process_name = raw_log.get("process_name") or raw_log.get("proc") or raw_log.get("ProcessName")
            command_line = raw_log.get("command_line") or raw_log.get("cmd") or raw_log.get("ProcessCommandLine")
            file_path = raw_log.get("file_path") or raw_log.get("file") or raw_log.get("TargetFilename")
            
            bytes_raw = raw_log.get("bytes_transferred") or raw_log.get("bytes") or raw_log.get("BytesSent", 0.0)
            try:
                bytes_transferred = float(bytes_raw)
            except Exception:
                bytes_transferred = 0.0

            status = raw_log.get("status") or raw_log.get("result") or raw_log.get("Status")
            if status:
                status = str(status).lower()

            # Keep the complete original raw log for forensics
            raw_string = json.dumps(raw_log)

            event = CanonicalEvent(
                timestamp=timestamp,
                log_source=log_source,
                severity=severity,
                username=username,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                action_type=action_type,
                process_name=process_name,
                command_line=command_line,
                file_path=file_path,
                bytes_transferred=bytes_transferred,
                status=status,
                raw_log=raw_string
            )
            return event

        except Exception as e:
            logger.error("Failed to normalize raw log", error=str(e), raw_log=raw_log)
            return None

    def normalize_batch(self, raw_logs: List[Dict[str, Any]]) -> List[CanonicalEvent]:
        normalized = []
        for log in raw_logs:
            event = self.normalize(log)
            if event:
                normalized.append(event)
        return normalized
