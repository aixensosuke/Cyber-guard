from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from src.orchestration.llm import LocalLLMClient
from src.orchestration.tools import collect_forensic_evidence, quarantine_host, disable_user_account
from src.utils.logging import get_logger
from src.config import Config

logger = get_logger("agent")

# Define LangGraph State schema
class AgentState(TypedDict):
    incident: Dict[str, Any]
    forensic_data: str
    mitigations_executed: List[str]
    playbook: Dict[str, Any]


class CyberGuardOrchestrator:
    def __init__(self):
        self.llm_client = LocalLLMClient()
        self._build_graph()

    def _build_graph(self):
        # Initialize LangGraph StateGraph
        builder = StateGraph(AgentState)

        # Define Nodes
        builder.add_node("gather_evidence", self.gather_evidence_node)
        builder.add_node("apply_containment", self.apply_containment_node)
        builder.add_node("generate_playbook", self.generate_playbook_node)

        # Define Edges / Transitions
        builder.set_entry_point("gather_evidence")
        builder.add_edge("gather_evidence", "apply_containment")
        builder.add_edge("apply_containment", "generate_playbook")
        builder.add_edge("generate_playbook", END)

        # Compile graph
        self.workflow = builder.compile()

    def gather_evidence_node(self, state: AgentState) -> Dict[str, Any]:
        """
        Gathers process list and active connections on compromised hosts.
        """
        incident = state["incident"]
        logger.info("Agent State: Gathering Forensic Evidence", incident_id=incident["incident_id"])
        
        # Identify endpoints/hosts in entities
        compromised_hosts = []
        for entity in incident.get("entities", []):
            if "srv" in entity.lower() or "dc" in entity.lower() or "wkstn" in entity.lower():
                compromised_hosts.append(entity)
        
        # If no specific host is identified, default to core server
        if not compromised_hosts:
            compromised_hosts.append("DB-SRV.bank.local")

        evidence_logs = []
        for host in compromised_hosts:
            evidence = collect_forensic_evidence(host)
            evidence_logs.append(f"--- Forensic Evidence for {host} ---\n{evidence}")

        combined_evidence = "\n\n".join(evidence_logs)
        return {
            "forensic_data": combined_evidence
        }

    def apply_containment_node(self, state: AgentState) -> Dict[str, Any]:
        """
        Applies network and account quarantining based on CFR severity score.
        """
        incident = state["incident"]
        cfr_score = incident.get("cfr_score", 0.0)
        mitigations = []

        logger.info("Agent State: Applying Containment Rules", incident_id=incident["incident_id"], cfr_score=cfr_score)

        # CFR threshold (CFR >= 5.0) for active automated mitigation
        if cfr_score >= 5.0:
            logger.warn("CFR score above threshold. Executing active containment tools.", incident_id=incident["incident_id"])
            
            # Find hosts to isolate
            hosts_to_quarantine = []
            users_to_disable = []

            for entity in incident.get("entities", []):
                # Classify entity for tool execution
                if "srv" in entity.lower() or "dc" in entity.lower() or "wkstn" in entity.lower():
                    hosts_to_quarantine.append(entity)
                elif "admin" in entity.lower() or "user" in entity.lower() or entity in ["admin", "root"]:
                    users_to_disable.append(entity)

            # Safeguard default values if entities lists are empty
            if not hosts_to_quarantine:
                hosts_to_quarantine.append("DB-SRV.bank.local")
            if not users_to_disable:
                users_to_disable.append("admin")

            # Execute host quarantine
            for host in hosts_to_quarantine:
                res = quarantine_host(host)
                mitigations.append(f"Quarantined Host: {host}")

            # Execute account suspension
            for user in users_to_disable:
                res = disable_user_account(user)
                mitigations.append(f"Suspended Account: {user}")
        else:
            logger.info("CFR score below active mitigation threshold. Skipping active block actions.", incident_id=incident["incident_id"])

        return {
            "mitigations_executed": mitigations
        }

    def generate_playbook_node(self, state: AgentState) -> Dict[str, Any]:
        """
        Drafts the incident report playbook using the offline LLM generator.
        """
        incident = state["incident"]
        logger.info("Agent State: Generating Incident Playbook", incident_id=incident["incident_id"])
        
        # Append collected forensics and execution records to the incident context for LLM ingestion
        incident_context = incident.copy()
        incident_context["forensics"] = state.get("forensic_data", "")
        incident_context["mitigations_applied"] = state.get("mitigations_executed", [])

        # Call local generator client
        playbook_payload = self.llm_client.generate_playbook(incident_context)

        # Write playbook output file to the disk
        pb_filename = Config.PLAYBOOK_DIR / f"playbook_{incident['incident_id']}.md"
        with open(pb_filename, "w", encoding="utf-8") as f:
            f.write(playbook_payload["playbook_content"])

        logger.info("Incident Playbook written to disk", path=str(pb_filename))
        
        return {
            "playbook": playbook_payload
        }

    def run(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the LangGraph pipeline synchronously.
        """
        initial_state = {
            "incident": incident,
            "forensic_data": "",
            "mitigations_executed": [],
            "playbook": {}
        }
        
        # Run workflow StateGraph
        final_state = self.workflow.invoke(initial_state)
        return final_state
