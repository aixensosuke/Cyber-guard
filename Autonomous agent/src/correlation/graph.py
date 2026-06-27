import networkx as nx
import uuid
from typing import List, Dict, Any, Tuple, Set
from datetime import datetime
from src.config import Config
from src.utils.logging import get_logger

logger = get_logger("correlation")

def map_mitre_attack_stage(event: Dict[str, Any]) -> str:
    """
    Maps a normalized security event to a MITRE ATT&CK stage based on indicators.
    """
    log_source = event.get("log_source", "")
    action_type = event.get("action_type", "")
    process_name = str(event.get("process_name") or "").lower()
    cmd_line = str(event.get("command_line") or "").lower()
    status = str(event.get("status") or "").lower()
    bytes_transferred = float(event.get("bytes_transferred") or 0.0)

    # 1. Exfiltration check
    if bytes_transferred > 10 * 1024 * 1024:  # Exfiltration limit (e.g. >10MB)
        return "Exfiltration"

    # 2. Firewall / port sweep check
    if log_source == "firewall" and status == "failure":
        return "Reconnaissance"

    # 3. Credential access check
    if action_type == "login_attempt" and status == "failure":
        return "Credential Access"
    if "mimikatz" in process_name or "sekurlsa" in cmd_line:
        return "Credential Access"

    # 4. Discovery check
    if any(disc in cmd_line for disc in ["whoami", "net user", "ipconfig", "netstat", "route print"]):
        return "Discovery"

    # 5. Privilege Escalation / Impact check
    if "vssadmin" in process_name and "delete shadows" in cmd_line:
        return "Impact"
    if "runas" in cmd_line or "sudo" in process_name:
        return "Privilege Escalation"

    # 6. Execution check
    if action_type == "process_spawn":
        return "Execution"
    if action_type == "login_attempt" and status == "success" and log_source == "ssh":
        return "Initial Access"

    return "Unknown"


class ThreatCorrelator:
    def __init__(self):
        self.graph = nx.Graph()

    def build_relationship_graph(self, events: List[Dict[str, Any]]):
        """
        Populates a NetworkX graph linking entities from events.
        """
        self.graph.clear()
        
        for e in events:
            ev_id = e["event_id"]
            user = e.get("username")
            src_ip = e.get("source_ip")
            dest_ip = e.get("destination_ip")
            proc = e.get("process_name")
            file_path = e.get("file_path")
            
            # Nodes represent entities; edges represent the event connecting them
            # Add nodes with types
            if user:
                self.graph.add_node(user, type="User")
            if src_ip:
                self.graph.add_node(src_ip, type="IP")
            if dest_ip:
                self.graph.add_node(dest_ip, type="IP")
            if proc:
                self.graph.add_node(proc, type="Process")
            if file_path:
                self.graph.add_node(file_path, type="File")

            # Add links based on context
            if user and src_ip:
                self.graph.add_edge(user, src_ip, event_id=ev_id)
            if src_ip and dest_ip:
                self.graph.add_edge(src_ip, dest_ip, event_id=ev_id)
            if user and proc:
                self.graph.add_edge(user, proc, event_id=ev_id)
            if proc and file_path:
                self.graph.add_edge(proc, file_path, event_id=ev_id)

    def collapse_into_incidents(self, anomalous_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups anomalous events into collapsed Incident objects based on shared graph components.
        """
        if not anomalous_events:
            return []

        # 1. Build a smaller graph containing only anomalous entities
        anomaly_graph = nx.Graph()
        event_map = {e["event_id"]: e for e in anomalous_events}
        
        for e in anomalous_events:
            ev_id = e["event_id"]
            user = e.get("username")
            src_ip = e.get("source_ip")
            dest_ip = e.get("destination_ip")
            
            # Extract nodes
            nodes = [n for n in [user, src_ip, dest_ip] if n]
            
            for node in nodes:
                # Assign entity tier if matching
                tier = Config.ENTITY_TIERS.get(node, 1)
                # Check for critical servers
                if "db" in str(node).lower():
                    tier = Config.ENTITY_TIERS.get("database_server", 3)
                elif "dc" in str(node).lower() or "domain" in str(node).lower():
                    tier = Config.ENTITY_TIERS.get("domain_controller", 3)
                
                anomaly_graph.add_node(node, tier=tier)

            # Draw links between entities in this event
            if len(nodes) > 1:
                for i in range(len(nodes)):
                    for j in range(i + 1, len(nodes)):
                        # Annotate edge with event_id
                        anomaly_graph.add_edge(nodes[i], nodes[j], event_id=ev_id)

        # 2. Extract connected components (subgraphs) representing distinct incidents
        components = list(nx.connected_components(anomaly_graph))
        incidents = []

        for comp in components:
            incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
            sub_g = anomaly_graph.subgraph(comp)
            
            # Find all event IDs linked to this component
            related_event_ids = set()
            for u, v, data in sub_g.edges(data=True):
                if "event_id" in data:
                    related_event_ids.add(data["event_id"])
            
            # Collect the actual events
            related_events = [event_map[ev_id] for ev_id in related_event_ids if ev_id in event_map]
            if not related_events:
                continue

            # Determine the overall timeline
            timestamps = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in related_events]
            min_ts = min(timestamps).isoformat()
            max_ts = max(timestamps).isoformat()

            # Identify entities involved
            entities = list(comp)

            # Determine maximum entity tier in the graph
            max_tier = max([sub_g.nodes[node].get("tier", 1) for node in comp])

            # Determine MITRE ATT&CK stage progression
            stages = {map_mitre_attack_stage(e) for e in related_events}
            # Remove "Unknown" if other stages are present to make report cleaner
            if len(stages) > 1 and "Unknown" in stages:
                stages.remove("Unknown")

            # Breadth = diameter or size of the entity component
            # Larger components represent attacks spreading across more systems
            breadth = len(comp)

            # Find the most advanced stage in stages
            # Map stages to weights
            stage_weights = [(s, Config.ATTACK_STAGE_WEIGHTS.get(s, 0.0)) for s in stages]
            highest_stage = max(stage_weights, key=lambda x: x[1])[0] if stage_weights else "Unknown"

            incidents.append({
                "incident_id": incident_id,
                "timestamp": min_ts,
                "end_timestamp": max_ts,
                "entities": entities,
                "max_entity_tier": max_tier,
                "correlation_breadth": breadth,
                "mitre_stages": list(stages),
                "highest_mitre_stage": highest_stage,
                "events": related_events
            })

        logger.info("Collapsed anomalous events into incidents", count=len(incidents))
        return incidents
