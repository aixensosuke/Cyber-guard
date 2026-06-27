import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any

from src.config import Config
from src.utils.logging import get_logger
from src.utils.generator import SecurityLogGenerator
from src.ingestion.normalizer import LogNormalizer
from src.persistence.database import CyberGuardDB
from src.detection.preprocessor import LogFeatureExtractor
from src.detection.detector import CyberGuardDetector
from src.ueba.analytics import UEBAEngine
from src.correlation.graph import ThreatCorrelator
from src.correlation.CFR import CFRCalculator
from src.orchestration.agent import CyberGuardOrchestrator

logger = get_logger("pipeline_runner")

def print_banner():
    banner = """
======================================================================
               CYBERGUARD-IR 7-LAYER PIPELINE RUNNER                  
======================================================================
[INFO] Local Time: 2026-05-20T21:22:29+05:30
[INFO] Target Compliance: RBI CSCRF, EU DORA, PCI-DSS
[INFO] Mode: 100% Offline, Local ML Ensemble & LangGraph Orchestration
======================================================================
    """
    print(banner)

def main():
    print_banner()

    # ----------------------------------------------------
    # LAYER 1: Ingestion & Normalization
    # ----------------------------------------------------
    logger.info("Starting Layer 1: Ingestion & Normalization")
    generator = SecurityLogGenerator(seed=101)
    normalizer = LogNormalizer(deduplication_window_seconds=60)

    # Generate baseline normal activity
    raw_baseline = generator.generate_baseline(num_events=250)
    # Generate attack pattern starting right after the baseline
    last_baseline_time = datetime.utcnow()
    raw_attack = generator.generate_attack_sequence(start_time=last_baseline_time)
    
    # Run through normalizer
    norm_baseline = normalizer.normalize_batch(raw_baseline)
    norm_attack = normalizer.normalize_batch(raw_attack)
    
    logger.info(
        "Ingested logs", 
        raw_baseline=len(raw_baseline), 
        norm_baseline=len(norm_baseline),
        raw_attack=len(raw_attack), 
        norm_attack=len(norm_attack)
    )

    # Combine all normalized events for evaluation
    all_events = norm_baseline + norm_attack
    all_dicts = [e.to_dict() for e in all_events]

    # ----------------------------------------------------
    # LAYER 2: Persistence
    # ----------------------------------------------------
    logger.info("Starting Layer 2: Persistence Setup")
    db = CyberGuardDB()
    db.initialize_storage()
    
    # Save all events to database
    db.save_events(all_events)

    # ----------------------------------------------------
    # LAYER 3 & 4: Anomaly Detection & UEBA Profiling
    # ----------------------------------------------------
    logger.info("Starting Layer 3 & 4: Detection Training & Behavioral Profiling")
    
    # 1. Fit Preprocessor on baseline
    baseline_dicts = [e.to_dict() for e in norm_baseline]
    preprocessor = LogFeatureExtractor()
    preprocessor.fit(baseline_dicts)
    
    # 2. Fit PyOD Ensemble on baseline features
    X_baseline = preprocessor.transform(baseline_dicts)
    detector = CyberGuardDetector(contamination=Config.CONTAMINATION_RATE)
    detector.fit(X_baseline)

    # 3. Build UEBA baselines on baseline logs
    ueba = UEBAEngine()
    ueba.build_baselines(baseline_dicts)

    # 4. Perform inference on all events (baseline + attack)
    logger.info("Evaluating all events for anomalies and behavioral deviations...")
    X_all = preprocessor.transform(all_dicts)
    anomaly_labels, anomaly_scores = detector.predict(X_all)

    # Map events to their anomaly and UEBA score
    event_scores = {}
    anomalous_events = []

    for i, event_dict in enumerate(all_dicts):
        ev_id = event_dict["event_id"]
        
        # Calculate UEBA deviation score
        ueba_score = ueba.evaluate_event(event_dict)
        
        # Store scores for CFR calculation later
        event_scores[ev_id] = (float(anomaly_scores[i]), float(ueba_score))

        # Check triggers: either flagged by ML ensemble (label == 1) OR high UEBA deviation (score > 0.5)
        if anomaly_labels[i] == 1 or ueba_score > 0.5:
            # We flag this log as anomalous for correlation
            anomalous_events.append(event_dict)
            
            # Update baseline with this anomalous event (novelty expansion check)
            ueba.update_baselines_with_event(event_dict)

    logger.info(
        "Detection phase completed", 
        total_evaluated=len(all_dicts), 
        flagged_anomalies=len(anomalous_events)
    )

    # ----------------------------------------------------
    # LAYER 5 & 6: Correlation Graph & CFR Scoring
    # ----------------------------------------------------
    logger.info("Starting Layer 5 & 6: NetworkX Correlation & CFR Scoring")
    correlator = ThreatCorrelator()
    # Populates full relationship structure
    correlator.build_relationship_graph(all_dicts)
    
    # Collapse anomalous alerts into incidents based on graph components
    incidents = correlator.collapse_into_incidents(anomalous_events)
    logger.info("Threat correlation completed", collapsed_incidents=len(incidents))

    # Score each incident using CFR
    cfr_calculator = CFRCalculator()
    scored_incidents = []
    
    for incident in incidents:
        cfr_score = cfr_calculator.calculate_score(incident, event_scores)
        # Save incident to database
        db.save_incident(incident)
        scored_incidents.append(incident)

    # Sort incidents by severity
    scored_incidents.sort(key=lambda x: x["cfr_score"], reverse=True)

    # ----------------------------------------------------
    # LAYER 7: LangGraph Orchestration & Response Playbooks
    # ----------------------------------------------------
    logger.info("Starting Layer 7: LangGraph Response Orchestration")
    orchestrator = CyberGuardOrchestrator()

    for idx, incident in enumerate(scored_incidents):
        logger.info(
            "Orchestrating response for Incident", 
            index=idx+1, 
            incident_id=incident["incident_id"],
            cfr_score=incident["cfr_score"],
            mitre_stage=incident["highest_mitre_stage"]
        )
        
        # Run state machine flow
        final_state = orchestrator.run(incident)
        
        # Save playbook to database
        playbook_payload = final_state["playbook"]
        db.save_playbook(playbook_payload)

        # Print playbooks
        print(f"\n=======================================================")
        print(f"Playbook Generated for Incident {incident['incident_id']}")
        print(f"=======================================================")
        print(f"CFR Score: {incident['cfr_score']} (MITRE Stage: {incident['highest_mitre_stage']})")
        print(f"Mitigations Executed: {final_state['mitigations_executed']}")
        print(f"Playbook Saved to: {Config.PLAYBOOK_DIR}/playbook_{incident['incident_id']}.md")
        print(f"-------------------------------------------------------")
        # Print a snippet of the executive summary from the playbook
        summary_lines = playbook_payload["playbook_content"].split("\n")
        print("\n".join(summary_lines[6:15]))
        print(f"=======================================================\n")

    db.close()
    logger.info("CyberGuard-IR Pipeline Execution Complete")

if __name__ == "__main__":
    main()
