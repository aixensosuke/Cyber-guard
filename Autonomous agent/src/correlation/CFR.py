from typing import Dict, Any, List, Tuple
from src.config import Config
from src.utils.logging import get_logger

logger = get_logger("cfr")

class CFRCalculator:
    def __init__(self):
        self.weights = Config.CFR_WEIGHTS
        self.stage_weights = Config.ATTACK_STAGE_WEIGHTS

    def calculate_score(self, incident: Dict[str, Any], event_scores: Dict[str, Tuple[float, float]]) -> float:
        """
        Calculates the CFR score for an incident on a scale of 0.0 to 10.0.
        event_scores maps event_id -> (anomaly_score, ueba_deviation).
        """
        events = incident.get("events", [])
        if not events:
            return 0.0

        # 1. Compute Mean Anomaly Score
        scores = []
        ueba_devs = []
        for e in events:
            ev_id = e["event_id"]
            if ev_id in event_scores:
                scores.append(event_scores[ev_id][0])
                ueba_devs.append(event_scores[ev_id][1])
            else:
                scores.append(0.0)
                ueba_devs.append(0.0)
        
        avg_anomaly = float(sum(scores) / len(scores))
        max_ueba = float(max(ueba_devs)) if ueba_devs else 0.0

        # 2. Normalize Correlation Breadth (1 node = 0.1, 10+ nodes = 1.0)
        breadth = min(1.0, incident.get("correlation_breadth", 1) / 10.0)

        # 3. Retrieve MITRE ATT&CK Stage Weight
        highest_stage = incident.get("highest_mitre_stage", "Unknown")
        stage_weight = self.stage_weights.get(highest_stage, 0.0)

        # 4. Normalize Entity Tier (Tier 3 = 1.0, Tier 1 = 0.33)
        max_tier = incident.get("max_entity_tier", 1)
        entity_weight = float(max_tier / 3.0)

        # 5. Composite Formula Calculation
        weighted_anomaly = self.weights["anomaly"] * avg_anomaly
        weighted_ueba = self.weights["ueba"] * max_ueba
        weighted_correlation = self.weights["correlation"] * breadth
        weighted_attack = self.weights["attack_stage"] * stage_weight
        weighted_entity = self.weights["entity_tier"] * entity_weight

        raw_cfr = (
            weighted_anomaly + 
            weighted_ueba + 
            weighted_correlation + 
            weighted_attack + 
            weighted_entity
        )
        
        # Scale to 0.0 - 10.0
        cfr_score = round(raw_cfr * 10.0, 2)

        # Add breakdown to incident details for compliance auditing
        incident["cfr_breakdown"] = {
            "anomaly_score_avg": round(avg_anomaly, 4),
            "ueba_deviation_max": round(max_ueba, 4),
            "correlation_breadth_norm": round(breadth, 4),
            "attack_stage_weight": round(stage_weight, 4),
            "entity_tier_weight": round(entity_weight, 4),
            "weighted_anomaly": round(weighted_anomaly, 4),
            "weighted_ueba": round(weighted_ueba, 4),
            "weighted_correlation": round(weighted_correlation, 4),
            "weighted_attack": round(weighted_attack, 4),
            "weighted_entity": round(weighted_entity, 4),
        }
        incident["cfr_score"] = cfr_score

        logger.info(
            "CFR Score Calculated", 
            incident_id=incident["incident_id"], 
            cfr_score=cfr_score, 
            highest_stage=highest_stage
        )
        return cfr_score
