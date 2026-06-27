import numpy as np
import pandas as pd
from collections import defaultdict
from typing import List, Dict, Any
from datetime import datetime
from src.config import Config
from src.utils.logging import get_logger

logger = get_logger("ueba")

class UEBAEngine:
    def __init__(self):
        # Store entity historical activities
        # Entity can be a username or a source IP
        # Profiles: entity -> list of values per time window (e.g. hourly)
        self.entity_bytes_history = defaultdict(list)
        self.entity_counts_history = defaultdict(list)
        
        # Novelty detection: entity -> set of observed resources (destination IPs, ports, processes)
        self.entity_known_dests = defaultdict(set)
        self.entity_known_procs = defaultdict(set)

        # Baseline profiles containing mean & std
        # entity -> { "bytes_mean", "bytes_std", "count_mean", "count_std" }
        self.baselines = {}

    def build_baselines(self, events: List[Dict[str, Any]], window_hours: int = 1):
        """
        Builds historical baseline profiles for all users and source IPs
        by dividing the historical events into window_hours buckets.
        """
        if not events:
            logger.warn("No events to build UEBA baseline")
            return

        df = pd.DataFrame(events)
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"])
        
        # Group by entity (user and source_ip)
        for entity_type in ["username", "source_ip"]:
            for entity, group in df.groupby(entity_type):
                if not entity or pd.isna(entity):
                    continue
                
                # 1. Populate novelty caches
                if entity_type == "username":
                    if "process_name" in group.columns:
                        procs = group["process_name"].dropna().unique()
                        self.entity_known_procs[entity].update(procs)
                
                if "destination_ip" in group.columns:
                    dests = group["destination_ip"].dropna().unique()
                    self.entity_known_dests[entity].update(dests)

                # 2. Divide into time buckets to get statistics
                group = group.set_index("timestamp_dt")
                resampled = group.resample(f"{window_hours}h")
                
                bytes_series = resampled["bytes_transferred"].sum()
                counts_series = resampled["event_id"].count()
                
                self.entity_bytes_history[entity] = bytes_series.tolist()
                self.entity_counts_history[entity] = counts_series.tolist()
                
                # Calculate mean and standard deviation
                self.baselines[entity] = {
                    "bytes_mean": float(np.mean(bytes_series)),
                    "bytes_std": float(np.std(bytes_series)),
                    "count_mean": float(np.mean(counts_series)),
                    "count_std": float(np.std(counts_series)),
                }
                
        logger.info("UEBA baseline profiles built", entities_profiled=len(self.baselines))

    def evaluate_event(self, event: Dict[str, Any]) -> float:
        """
        Evaluates a single event and returns a deviation score in the range [0.0, 1.0].
        Calculates Z-score deviations and set novelty.
        """
        user = event.get("username")
        src_ip = event.get("source_ip")
        
        entities = [e for e in [user, src_ip] if e]
        if not entities:
            return 0.0

        scores = []
        
        for entity in entities:
            score = 0.0
            baseline = self.baselines.get(entity)
            
            if baseline:
                # 1. Byte volume deviation
                event_bytes = float(event.get("bytes_transferred") or 0.0)
                mean_bytes = baseline["bytes_mean"]
                std_bytes = baseline["bytes_std"]
                
                if std_bytes > 0:
                    z_bytes = (event_bytes - mean_bytes) / std_bytes
                else:
                    z_bytes = (event_bytes - mean_bytes) / 1.0 # fallback std
                    
                # Normalize Z-score to 0-1 scale
                # Z-score of 3.0 or higher represents anomalous behavior (Config.UEBA_Z_SCORE_THRESHOLD)
                byte_score = min(1.0, max(0.0, z_bytes / Config.UEBA_Z_SCORE_THRESHOLD))
                score = max(score, byte_score)

            # 2. Novelty detection
            dest_ip = event.get("destination_ip")
            if dest_ip and dest_ip in self.entity_known_dests:
                if dest_ip not in self.entity_known_dests[entity]:
                    # Accessing a new destination IP (novelty score)
                    score = max(score, 0.6) # Moderate anomaly flag for novel network destination
                    
            proc_name = event.get("process_name")
            if proc_name and proc_name in self.entity_known_procs:
                if proc_name not in self.entity_known_procs[entity]:
                    # Executing a new process
                    score = max(score, 0.7) # Higher anomaly flag for novel process execution

            scores.append(score)

        # Return the maximum deviation observed across associated entities
        return max(scores) if scores else 0.0

    def update_baselines_with_event(self, event: Dict[str, Any]):
        """
        Updates the internal baselines with newly observed events.
        """
        user = event.get("username")
        src_ip = event.get("source_ip")
        
        for entity in [user, src_ip]:
            if not entity:
                continue
                
            dest_ip = event.get("destination_ip")
            if dest_ip:
                self.entity_known_dests[entity].add(dest_ip)
                
            proc_name = event.get("process_name")
            if proc_name:
                self.entity_known_procs[entity].add(proc_name)
