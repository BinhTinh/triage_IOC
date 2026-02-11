import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.models.case import Case
from src.models.ioc import ValidatedIOC
from src.config.settings import settings
from src.models.timeline import Timeline
from src.core.narrative_generator import NarrativeGenerator
from src.core.visualization import TextVisualizer


@dataclass
class ForensicReport:
    case_id: str
    generated_at: datetime
    os_type: str
    os_version: str
    summary: dict
    iocs: dict
    mitre: dict
    recommendations: List[str]
    timeline: List[dict]


class ReportGenerator:
    def __init__(self, output_dir: Optional[str] = None):
        self.base_output_dir = Path(output_dir or settings.reports_dir)
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
        self.case_dir: Optional[Path] = None
    
    def create_case_directory(self, case: Case) -> Path:
        timestamp = datetime.now().strftime("%H-%M-%S_T_%d_%m_%Y")
        folder_name = f"CASE_{case.os_type.upper()}_{timestamp}"
        
        self.case_dir = self.base_output_dir / folder_name
        self.case_dir.mkdir(parents=True, exist_ok=True)
        
        plugins_dir = self.case_dir / "plugins"
        plugins_dir.mkdir(exist_ok=True)
        
        return self.case_dir
    
    def save_plugin_output(
        self,
        plugin_name: str,
        data: Any,
        success: bool,
        error: Optional[str] = None,
        execution_time: float = 0.0
    ) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created. Call create_case_directory first.")
        
        plugins_dir = self.case_dir / "plugins"
        
        safe_name = plugin_name.replace(".", "_").replace("/", "_")
        filename = f"{safe_name}.txt"
        filepath = plugins_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"{'='*80}\n")
            f.write(f"PLUGIN: {plugin_name}\n")
            f.write(f"{'='*80}\n")
            f.write(f"Execution Time: {datetime.now().isoformat()}\n")
            f.write(f"Duration: {execution_time:.2f} seconds\n")
            f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
            f.write(f"{'='*80}\n\n")
            
            if not success and error:
                f.write(f"ERROR:\n{error}\n\n")
            
            if data:
                f.write(f"RESULTS ({len(data) if isinstance(data, list) else 1} rows):\n")
                f.write(f"{'-'*80}\n\n")
                
                if isinstance(data, list):
                    for i, row in enumerate(data, 1):
                        f.write(f"[{i}]\n")
                        if isinstance(row, dict):
                            for key, value in row.items():
                                f.write(f"  {key}: {value}\n")
                        else:
                            f.write(f"  {row}\n")
                        f.write("\n")
                else:
                    f.write(str(data))
            else:
                f.write("No data returned.\n")
            
            f.write(f"\n{'='*80}\n")
            f.write(f"END OF {plugin_name}\n")
            f.write(f"{'='*80}\n")
        
        return str(filepath)
    
    def save_timeline(self, timeline: 'Timeline') -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "timeline.json"
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(timeline.to_dict(), f, indent=2, default=str)
        
        txt_filepath = self.case_dir / "timeline.txt"
        
        with open(txt_filepath, "w", encoding="utf-8") as f:
            f.write(f"{'='*80}\n")
            f.write(f"TIMELINE - {timeline.total_events} EVENTS\n")
            f.write(f"{'='*80}\n")
            f.write(f"Period: {timeline.start_time} to {timeline.end_time}\n\n")
            
            for event in timeline.events[:100]:
                f.write(f"[{event.timestamp}] {event.severity.value.upper()}\n")
                f.write(f"  {event.description}\n")
                f.write(f"  Source: {event.source_plugin}\n")
                
                if event.mitre_technique:
                    f.write(f"  MITRE: {event.mitre_technique}\n")
                
                for key, val in event.details.items():
                    if val and len(str(val)) < 100:
                        f.write(f"    {key}: {val}\n")
                
                f.write("\n")
            
            if timeline.total_events > 100:
                f.write(f"\n... and {timeline.total_events - 100} more events\n")
        
        return str(filepath)
    
    def save_attack_chain(self, attack_chain) -> str:
            if not self.case_dir:
                raise ValueError("Case directory not created.")
            
            import json
            filepath = self.case_dir / "attack_chain.json"
            
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(attack_chain.to_dict(), f, indent=2, default=str)
            
            txt_filepath = self.case_dir / "attack_chain.txt"
            
            with open(txt_filepath, "w", encoding="utf-8") as f:
                f.write(f"{'='*80}\n")
                f.write(f"ATTACK CHAIN ANALYSIS\n")
                f.write(f"{'='*80}\n\n")
                
                f.write(f"Initial Vector: {attack_chain.initial_vector or 'Unknown'}\n")
                f.write(f"Entry Point PID: {attack_chain.entry_point_pid or 'Unknown'}\n")
                f.write(f"Confidence: {attack_chain.confidence:.0%}\n")
                f.write(f"Stages Identified: {len(attack_chain.stages)}\n\n")
                
                f.write(f"{'='*80}\n")
                f.write(f"ATTACK NARRATIVE\n")
                f.write(f"{'='*80}\n\n")
                f.write(attack_chain.narrative)
                f.write("\n\n")
                
                f.write(f"{'='*80}\n")
                f.write(f"ATTACK STAGES DETAIL\n")
                f.write(f"{'='*80}\n\n")
                
                for stage_enum, stage_info in attack_chain.stages.items():
                    f.write(f"[{stage_enum.value.upper()}]\n")
                    f.write(f"  Kill Chain: {stage_info.kill_chain_stage.value}\n")
                    f.write(f"  Timestamp: {stage_info.timestamp or 'N/A'}\n")
                    f.write(f"  Description: {stage_info.description}\n")
                    f.write(f"  Confidence: {stage_info.confidence:.0%}\n")
                    f.write(f"  Processes: {', '.join(map(str, stage_info.processes))}\n")
                    
                    if stage_info.techniques:
                        f.write(f"  MITRE Techniques: {', '.join(stage_info.techniques)}\n")
                    
                    f.write(f"  Events: {len(stage_info.events)}\n")
                    f.write("\n")
                
                f.write(f"{'='*80}\n")
                f.write(f"PROCESS TREE\n")
                f.write(f"{'='*80}\n\n")
                
                def print_tree(node, indent=0):
                    prefix = "  " * indent
                    status = "🔴 MALICIOUS" if node.is_malicious else ("⚠️  SUSPICIOUS" if node.is_suspicious else "")
                    f.write(f"{prefix}├─ [{node.pid}] {node.name} {status}\n")
                    
                    if node.injections:
                        f.write(f"{prefix}   └─ Injections: {len(node.injections)}\n")
                    
                    for child in node.children:
                        print_tree(child, indent + 1)
                
                for root in attack_chain.process_tree:
                    print_tree(root)
            
            return str(filepath)
    
    def save_behavior_analysis(self, classification) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        import json
        filepath = self.case_dir / "behavior_analysis.json"
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(classification.to_dict(), f, indent=2)
        
        txt_filepath = self.case_dir / "behavior_analysis.txt"
        
        with open(txt_filepath, "w", encoding="utf-8") as f:
            f.write(f"{'='*80}\n")
            f.write(f"BEHAVIOR ANALYSIS & MALWARE CLASSIFICATION\n")
            f.write(f"{'='*80}\n\n")
            
            f.write(f"PRIMARY CLASSIFICATION\n")
            f.write(f"{'─'*80}\n")
            f.write(f"  Family: {classification.primary_family.value.upper().replace('_', ' ')}\n")
            f.write(f"  Confidence: {classification.confidence:.0%}\n\n")
            
            if classification.secondary_families:
                f.write(f"  Secondary Families:\n")
                for family in classification.secondary_families:
                    f.write(f"    - {family.value.replace('_', ' ').title()}\n")
                f.write("\n")
            
            f.write(f"BEHAVIORAL SUMMARY\n")
            f.write(f"{'─'*80}\n")
            f.write(classification.behavioral_summary)
            f.write("\n\n")
            
            f.write(f"CAPABILITIES (MITRE ATT&CK)\n")
            f.write(f"{'─'*80}\n")
            if classification.capabilities:
                for technique in classification.capabilities:
                    f.write(f"  - {technique}\n")
            else:
                f.write(f"  No specific techniques identified\n")
            f.write("\n")
            
            f.write(f"MATCHED BEHAVIOR PATTERNS ({len(classification.matched_patterns)})\n")
            f.write(f"{'─'*80}\n\n")
            
            sorted_matches = sorted(classification.matched_patterns, key=lambda x: x.confidence, reverse=True)
            
            for i, match in enumerate(sorted_matches, 1):
                f.write(f"[{i}] {match.pattern.name}\n")
                f.write(f"    ID: {match.pattern.pattern_id}\n")
                f.write(f"    Confidence: {match.confidence:.0%}\n")
                f.write(f"    Description: {match.pattern.description}\n")
                f.write(f"    Evidence: {len(match.evidence)} indicators\n")
                
                if match.pattern.mitre_techniques:
                    f.write(f"    MITRE: {', '.join(match.pattern.mitre_techniques)}\n")
                
                f.write("\n")
        
        return str(filepath)
    
    def save_visualizations(self, timeline, attack_chain, validated_iocs) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "visualizations.txt"
        
        with open(filepath, "w", encoding="utf-8") as f:
            timeline_chart = TextVisualizer.generate_timeline_chart(timeline)
            f.write(timeline_chart)
            f.write("\n\n")
            
            process_tree = TextVisualizer.generate_process_tree_diagram(attack_chain)
            f.write(process_tree)
            f.write("\n\n")
            
            attack_flow = TextVisualizer.generate_attack_flow_diagram(attack_chain)
            f.write(attack_flow)
            f.write("\n\n")
            
            stats = TextVisualizer.generate_statistics_chart(timeline, validated_iocs)
            f.write(stats)
        
        return str(filepath)
    
    def save_narrative(self, timeline, attack_chain, classification, validated_iocs) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        narrator = NarrativeGenerator()
        narrative = narrator.generate_full_narrative(
            timeline, attack_chain, classification, validated_iocs
        )
        
        filepath = self.case_dir / "narrative.txt"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(narrative)
        
        return str(filepath)

    def save_iocs_json(self, validated_iocs: List[ValidatedIOC], raw_iocs: List[dict] = None) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "iocs.json"
        
        ioc_data = {
            "generated_at": datetime.now().isoformat(),
            "total_iocs": len(validated_iocs),
            "summary": {
                "malicious": 0,
                "suspicious": 0,
                "benign": 0
            },
            "by_type": {},
            "iocs": {
                "malicious": [],
                "suspicious": [],
                "benign": []
            },
            "raw_extracted": raw_iocs or []
        }
        
        for v_ioc in validated_iocs:
            ioc_entry = {
                "type": v_ioc.ioc.ioc_type,
                "value": v_ioc.ioc.value,
                "confidence": v_ioc.final_confidence,
                "source_plugin": v_ioc.ioc.source_plugin,
                "context": v_ioc.ioc.context,
                "validation_reason": v_ioc.reason,
                "extracted_at": v_ioc.ioc.extracted_at.isoformat()
            }
            
            ioc_data["iocs"][v_ioc.verdict].append(ioc_entry)
            ioc_data["summary"][v_ioc.verdict] += 1
            
            ioc_type = v_ioc.ioc.ioc_type
            if ioc_type not in ioc_data["by_type"]:
                ioc_data["by_type"][ioc_type] = {"count": 0, "malicious": 0, "suspicious": 0, "benign": 0}
            ioc_data["by_type"][ioc_type]["count"] += 1
            ioc_data["by_type"][ioc_type][v_ioc.verdict] += 1
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(ioc_data, f, indent=2, ensure_ascii=False, default=str)
        
        return str(filepath)
    
    
    def save_summary(
        self,
        case: Case,
        validated_iocs: List[ValidatedIOC],
        mitre_mapping: dict,
        plugin_results: Dict[str, dict]
    ) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "SUMMARY.txt"
        
        malicious = [i for i in validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in validated_iocs if i.verdict == "suspicious"]
        benign = [i for i in validated_iocs if i.verdict == "benign"]
        
        threat_level, threat_score = self._calculate_threat_level(malicious, suspicious, mitre_mapping)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"{'#'*80}\n")
            f.write(f"#{'FORENSIC ANALYSIS SUMMARY REPORT':^78}#\n")
            f.write(f"{'#'*80}\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"CASE INFORMATION\n")
            f.write(f"{'='*80}\n")
            f.write(f"  Case ID:           {case.id}\n")
            f.write(f"  Dump Path:         {case.dump_path}\n")
            f.write(f"  Dump Hash:         {case.dump_hash}\n")
            f.write(f"  Operating System:  {case.os_type.upper()} {case.os_version} ({case.os_arch})\n")
            f.write(f"  Analysis Goal:     {case.goal}\n")
            f.write(f"  Analysis Started:  {case.created_at.isoformat()}\n")
            f.write(f"  Report Generated:  {datetime.now().isoformat()}\n")
            f.write(f"  Duration:          {(datetime.now() - case.created_at).total_seconds():.0f} seconds\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"THREAT ASSESSMENT\n")
            f.write(f"{'='*80}\n\n")
            
            level_bar = self._generate_threat_bar(threat_level)
            f.write(f"  THREAT LEVEL:  [{threat_level}]\n")
            f.write(f"  THREAT SCORE:  {threat_score}/100\n\n")
            f.write(f"  {level_bar}\n\n")
            
            f.write(f"  Assessment Criteria:\n")
            f.write(f"  - CRITICAL (80-100): Active compromise, immediate action required\n")
            f.write(f"  - HIGH     (60-79):  Confirmed malicious activity detected\n")
            f.write(f"  - MEDIUM   (40-59):  Suspicious indicators requiring investigation\n")
            f.write(f"  - LOW      (0-39):   Minimal indicators, likely clean\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"IOC SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"  Total IOCs Extracted:    {len(validated_iocs)}\n")
            f.write(f"  ├── Malicious:           {len(malicious)} {'⚠️  ALERT' if len(malicious) > 0 else ''}\n")
            f.write(f"  ├── Suspicious:          {len(suspicious)}\n")
            f.write(f"  └── Benign:              {len(benign)}\n\n")
            f.write(f"{'='*80}\n")
            f.write(f"TIMELINE SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"{'='*80}\n")
            f.write(f"ATTACK CHAIN SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            
            if hasattr(case, 'attack_chain') and case.attack_chain:
                chain = case.attack_chain
                f.write(f"  Initial Vector: {chain.initial_vector or 'Unknown'}\n")
                f.write(f"  Entry Point: PID {chain.entry_point_pid or 'Unknown'}\n")
                f.write(f"  Attack Stages: {len(chain.stages)}\n")
                f.write(f"  Confidence: {chain.confidence:.0%}\n\n")
                
                if chain.stages:
                    f.write(f"  Attack Progression:\n")
                    sorted_stages = sorted(chain.stages.items(), key=lambda x: x[1].timestamp if x[1].timestamp else datetime.max)
                    
                    for stage_enum, stage_info in sorted_stages:
                        time_str = stage_info.timestamp.strftime("%H:%M:%S") if stage_info.timestamp else "N/A"
                        f.write(f"    [{time_str}] {stage_enum.value.replace('_', ' ').title()}\n")
                    
                    f.write("\n")
            else:
                f.write(f"  Attack chain not available\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"MALWARE CLASSIFICATION\n")
            f.write(f"{'='*80}\n\n")
            
            if hasattr(case, 'malware_classification') and case.malware_classification:
                classification = case.malware_classification
                f.write(f"  Primary Family: {classification.primary_family.value.upper().replace('_', ' ')}\n")
                f.write(f"  Confidence: {classification.confidence:.0%}\n")
                
                if classification.secondary_families:
                    f.write(f"  Secondary Families: {', '.join(f.value.replace('_', ' ').title() for f in classification.secondary_families)}\n")
                
                f.write(f"  Matched Patterns: {len(classification.matched_patterns)}\n")
                f.write(f"  Capabilities: {len(classification.capabilities)} MITRE techniques\n\n")
                
                high_conf_patterns = [m for m in classification.matched_patterns if m.confidence > 0.7]
                if high_conf_patterns:
                    f.write(f"  High Confidence Behaviors:\n")
                    for match in high_conf_patterns[:5]:
                        f.write(f"    - {match.pattern.name} ({match.confidence:.0%})\n")
                    f.write("\n")
            else:
                f.write(f"  Malware classification not available\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"VISUALIZATIONS\n")
            f.write(f"{'='*80}\n\n")
            
            if hasattr(case, 'timeline') and case.timeline:
                stats_chart = TextVisualizer.generate_statistics_chart(
                    case.timeline, 
                    validated_iocs
                )
                f.write(stats_chart)
                f.write("\n\n")
            
            f.write(f"See attack_chain.txt for process tree and attack flow diagrams.\n")
            f.write(f"See narrative.txt for detailed attack story and recommendations.\n\n")
            if case.timeline:
                timeline = case.timeline
                f.write(f"  Total Events: {timeline.total_events}\n")
                f.write(f"  Time Range: {timeline.start_time} to {timeline.end_time}\n\n")
                
                f.write(f"  Event Types:\n")
                for event_type, count in sorted(timeline.event_types.items(), key=lambda x: -x[1]):
                    f.write(f"    - {event_type}: {count}\n")
                f.write("\n")
                
                from src.models.timeline import EventSeverity
                high_events = timeline.get_events_by_severity(EventSeverity.HIGH)
                
                if high_events:
                    f.write(f"  High Severity Events (top 10):\n")
                    for event in high_events[:10]:
                        f.write(f"    [{event.timestamp}] {event.description}\n")
                    f.write("\n")
            else:
                f.write(f"  Timeline not available\n\n")
            
            by_type = {}
            for ioc in validated_iocs:
                t = ioc.ioc.ioc_type
                if t not in by_type:
                    by_type[t] = 0
                by_type[t] += 1
            
            f.write(f"  By Type:\n")
            for ioc_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
                f.write(f"    - {ioc_type}: {count}\n")
            f.write("\n")
            
            if malicious:
                f.write(f"{'='*80}\n")
                f.write(f"MALICIOUS INDICATORS (CRITICAL FINDINGS)\n")
                f.write(f"{'='*80}\n\n")
                
                for i, ioc in enumerate(malicious[:20], 1):
                    f.write(f"  [{i}] {ioc.ioc.ioc_type.upper()}: {ioc.ioc.value}\n")
                    f.write(f"      Confidence: {ioc.final_confidence:.0%}\n")
                    f.write(f"      Source: {ioc.ioc.source_plugin}\n")
                    f.write(f"      Reason: {ioc.reason}\n")
                    if ioc.ioc.context.get("technique"):
                        f.write(f"      MITRE ATT&CK: {ioc.ioc.context['technique']}\n")
                    f.write("\n")
                
                if len(malicious) > 20:
                    f.write(f"  ... and {len(malicious) - 20} more malicious indicators\n\n")
            
            if suspicious:
                f.write(f"{'='*80}\n")
                f.write(f"SUSPICIOUS INDICATORS (REQUIRES INVESTIGATION)\n")
                f.write(f"{'='*80}\n\n")
                
                for i, ioc in enumerate(suspicious[:10], 1):
                    f.write(f"  [{i}] {ioc.ioc.ioc_type.upper()}: {ioc.ioc.value}\n")
                    f.write(f"      Confidence: {ioc.final_confidence:.0%}\n")
                    f.write(f"      Source: {ioc.ioc.source_plugin}\n")
                    f.write("\n")
                
                if len(suspicious) > 10:
                    f.write(f"  ... and {len(suspicious) - 10} more suspicious indicators\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"MITRE ATT&CK MAPPING\n")
            f.write(f"{'='*80}\n\n")
            
            techniques = mitre_mapping.get("techniques", [])
            if techniques:
                f.write(f"  Detected Techniques: {len(techniques)}\n\n")
                
                tactics_grouped = {}
                for tech in techniques:
                    tactic = tech.get("tactic", "Unknown")
                    if tactic not in tactics_grouped:
                        tactics_grouped[tactic] = []
                    tactics_grouped[tactic].append(tech)
                
                for tactic, techs in tactics_grouped.items():
                    f.write(f"  [{tactic}]\n")
                    for tech in techs:
                        f.write(f"    - {tech['id']}: {tech['name']} ({tech.get('ioc_count', 0)} IOCs)\n")
                    f.write("\n")
            else:
                f.write("  No MITRE ATT&CK techniques mapped.\n\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"PLUGIN EXECUTION SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            
            successful_plugins = sum(1 for r in plugin_results.values() if r.get("success", False))
            failed_plugins = len(plugin_results) - successful_plugins
            
            f.write(f"  Total Plugins Executed: {len(plugin_results)}\n")
            f.write(f"  ├── Successful: {successful_plugins}\n")
            f.write(f"  └── Failed: {failed_plugins}\n\n")
            
            f.write(f"  Plugin Details:\n")
            for plugin_name, result in plugin_results.items():
                status = "✓" if result.get("success", False) else "✗"
                rows = result.get("rows", 0)
                f.write(f"    [{status}] {plugin_name}: {rows} rows\n")
            f.write("\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"RECOMMENDATIONS\n")
            f.write(f"{'='*80}\n\n")
            
            recommendations = self._generate_recommendations(malicious, suspicious, mitre_mapping, threat_level)
            for i, rec in enumerate(recommendations, 1):
                f.write(f"  {i}. {rec}\n")
            f.write("\n")
            
            f.write(f"{'='*80}\n")
            f.write(f"FILES IN THIS REPORT\n")
            f.write(f"{'='*80}\n\n")
            
            case_name = self.case_dir.name if self.case_dir else "CASE"
            
            f.write(f"  {case_name}/\n")
            f.write(f"  ├── SUMMARY.txt               (This file - Executive summary)\n")
            f.write(f"  ├── narrative.txt             (Detailed attack story & recommendations)\n")
            f.write(f"  ├── timeline.txt              (Chronological event timeline)\n")
            f.write(f"  ├── timeline.json             (Machine-readable timeline)\n")
            f.write(f"  ├── attack_chain.txt          (Attack progression analysis)\n")
            f.write(f"  ├── attack_chain.json         (Machine-readable attack chain)\n")
            f.write(f"  ├── behavior_analysis.txt     (Malware classification & patterns)\n")
            f.write(f"  ├── behavior_analysis.json    (Machine-readable behavior data)\n")
            f.write(f"  ├── visualizations.txt        (Charts and diagrams)\n")
            f.write(f"  ├── iocs.json                 (All indicators of compromise)\n")
            f.write(f"  └── plugins/                  (Raw Volatility plugin outputs)\n")
            
            plugins_dir = self.case_dir / "plugins"
            if plugins_dir.exists():
                plugin_files = sorted(list(plugins_dir.glob("*.txt")))[:3]
                for pf in plugin_files:
                    f.write(f"      ├── {pf.name}\n")
                f.write(f"      └── ... ({len(list(plugins_dir.glob('*.txt')))} plugin outputs)\n\n")
            
            f.write(f"QUICK START:\n")
            f.write(f"  1. Read SUMMARY.txt for overview (you are here)\n")
            f.write(f"  2. Read narrative.txt for detailed story\n")
            f.write(f"  3. Review attack_chain.txt for attack progression\n")
            f.write(f"  4. Check behavior_analysis.txt for malware classification\n")
            f.write(f"  5. Examine visualizations.txt for charts and diagrams\n")
        return str(filepath)
    
    def _calculate_threat_level(
        self,
        malicious: List[ValidatedIOC],
        suspicious: List[ValidatedIOC],
        mitre_mapping: dict
    ) -> tuple:
        score = 0
        
        score += len(malicious) * 10
        score += len(suspicious) * 3
        
        techniques = mitre_mapping.get("techniques", [])
        score += len(techniques) * 5
        
        critical_techniques = ["T1055", "T1059.001", "T1105", "T1071"]
        for tech in techniques:
            if tech.get("id") in critical_techniques:
                score += 10
        
        injection_iocs = [i for i in malicious if i.ioc.ioc_type == "injection"]
        score += len(injection_iocs) * 15
        
        score = min(100, score)
        
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return level, score
    
    def _generate_threat_bar(self, level: str) -> str:
        bars = {
            "LOW": "[████░░░░░░░░░░░░░░░░] LOW",
            "MEDIUM": "[████████░░░░░░░░░░░░] MEDIUM",
            "HIGH": "[████████████████░░░░] HIGH",
            "CRITICAL": "[████████████████████] CRITICAL ⚠️"
        }
        return bars.get(level, "[░░░░░░░░░░░░░░░░░░░░] UNKNOWN")
    
    def _generate_recommendations(
        self,
        malicious: List[ValidatedIOC],
        suspicious: List[ValidatedIOC],
        mitre_mapping: dict,
        threat_level: str
    ) -> List[str]:
        recommendations = []
        
        if threat_level == "CRITICAL":
            recommendations.append("[IMMEDIATE] Isolate affected system from network")
            recommendations.append("[IMMEDIATE] Preserve all evidence and memory dumps")
            recommendations.append("[IMMEDIATE] Notify incident response team")
        
        malicious_ips = [i.ioc.value for i in malicious if i.ioc.ioc_type == "ip"]
        if malicious_ips:
            recommendations.append(f"[HIGH] Block malicious IPs at firewall: {', '.join(malicious_ips[:5])}")
        
        malicious_domains = [i.ioc.value for i in malicious if i.ioc.ioc_type == "domain"]
        if malicious_domains:
            recommendations.append(f"[HIGH] Block malicious domains in DNS/proxy: {', '.join(malicious_domains[:5])}")
        
        malicious_hashes = [i.ioc.value for i in malicious if i.ioc.ioc_type in ["md5", "sha1", "sha256"]]
        if malicious_hashes:
            recommendations.append("[HIGH] Add file hashes to EDR/AV blocklist")
        
        injections = [i for i in malicious if i.ioc.ioc_type == "injection"]
        if injections:
            recommendations.append("[HIGH] Investigate process injection - possible active malware")
        
        for tech in mitre_mapping.get("techniques", [])[:3]:
            for rec in tech.get("recommendations", [])[:1]:
                recommendations.append(f"[MEDIUM] {rec}")
        
        if suspicious:
            recommendations.append("[MEDIUM] Review suspicious indicators for false positive assessment")
        
        recommendations.append("[STANDARD] Document all findings in incident tracking system")
        recommendations.append("[STANDARD] Conduct follow-up analysis on related systems")
        recommendations.append("[STANDARD] Review and update detection rules based on findings")
        
        return recommendations[:15]
    
    def generate(
        self,
        case: Case,
        validated_iocs: List[ValidatedIOC],
        mitre_mapping: dict
    ) -> ForensicReport:
        malicious = [i for i in validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in validated_iocs if i.verdict == "suspicious"]
        
        threat_level, threat_score = self._calculate_threat_level(malicious, suspicious, mitre_mapping)
        recommendations = self._generate_recommendations(malicious, suspicious, mitre_mapping, threat_level)
        timeline = self._generate_timeline(validated_iocs)
        
        return ForensicReport(
            case_id=case.id,
            generated_at=datetime.now(),
            os_type=case.os_type,
            os_version=case.os_version,
            summary={
                "threat_level": threat_level,
                "threat_score": threat_score,
                "total_iocs": len(validated_iocs),
                "malicious": len(malicious),
                "suspicious": len(suspicious),
                "techniques_detected": mitre_mapping.get("total_techniques", 0),
                "analysis_duration_minutes": int((datetime.now() - case.created_at).total_seconds() // 60)
            },
            iocs={
                "malicious": [self._ioc_to_dict(i) for i in malicious],
                "suspicious": [self._ioc_to_dict(i) for i in suspicious[:20]]
            },
            mitre=mitre_mapping,
            recommendations=recommendations,
            timeline=timeline
        )
    
    def _generate_timeline(self, validated_iocs: List[ValidatedIOC]) -> List[dict]:
        events = []
        for ioc in validated_iocs:
            if ioc.verdict == "benign":
                continue
            events.append({
                "timestamp": ioc.ioc.extracted_at.isoformat(),
                "type": ioc.ioc.ioc_type,
                "value": ioc.ioc.value[:100],
                "verdict": ioc.verdict,
                "source": ioc.ioc.source_plugin,
                "technique": ioc.ioc.context.get("technique", "N/A")
            })
        return sorted(events, key=lambda x: x["timestamp"])[:50]
    
    def _ioc_to_dict(self, validated: ValidatedIOC) -> dict:
        return {
            "type": validated.ioc.ioc_type,
            "value": validated.ioc.value,
            "confidence": validated.final_confidence,
            "verdict": validated.verdict,
            "reason": validated.reason,
            "source": validated.ioc.source_plugin,
            "context": validated.ioc.context,
            "technique": validated.ioc.context.get("technique")
        }
    
    def save_json(self, report: ForensicReport) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "report.json"
        
        report_dict = {
            "case_id": report.case_id,
            "generated_at": report.generated_at.isoformat(),
            "os_type": report.os_type,
            "os_version": report.os_version,
            "summary": report.summary,
            "iocs": report.iocs,
            "mitre": report.mitre,
            "recommendations": report.recommendations,
            "timeline": report.timeline
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        return str(filepath)
    

    # src/core/report_generator.py (add method)

    def save_timeline(self, timeline: 'Timeline') -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "timeline.json"
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(timeline.to_dict(), f, indent=2, default=str)
        
        txt_filepath = self.case_dir / "timeline.txt"
        
        with open(txt_filepath, "w", encoding="utf-8") as f:
            f.write(f"{'='*80}\n")
            f.write(f"TIMELINE - {timeline.total_events} EVENTS\n")
            f.write(f"{'='*80}\n")
            f.write(f"Period: {timeline.start_time} to {timeline.end_time}\n\n")
            
            for event in timeline.events:
                f.write(f"[{event.timestamp}] {event.severity.value.upper()}\n")
                f.write(f"  Type: {event.event_type.value}\n")
                f.write(f"  {event.description}\n")
                f.write(f"  Source: {event.source_plugin}\n")
                
                if event.mitre_technique:
                    f.write(f"  MITRE: {event.mitre_technique}\n")
                
                for key, val in event.details.items():
                    if val and key not in ["hexdump"]:
                        f.write(f"    {key}: {val}\n")
                
                f.write("\n")
        
        return str(filepath)

    
    def save_markdown(self, report: ForensicReport) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")
        
        filepath = self.case_dir / "report.md"
        md_content = self._generate_markdown(report)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        
        return str(filepath)
    
    def _generate_markdown(self, report: ForensicReport) -> str:
        md = f"""# Forensic Analysis Report

## Case Information
- **Case ID**: {report.case_id}
- **Generated**: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
- **OS**: {report.os_type} {report.os_version}

## Executive Summary

| Metric | Value |
|--------|-------|
| **Threat Level** | {report.summary['threat_level']} |
| **Threat Score** | {report.summary['threat_score']}/100 |
| **Total IOCs** | {report.summary['total_iocs']} |
| **Malicious** | {report.summary['malicious']} |
| **Suspicious** | {report.summary['suspicious']} |
| **ATT&CK Techniques** | {report.summary['techniques_detected']} |

## Recommendations

"""
        for i, rec in enumerate(report.recommendations, 1):
            md += f"{i}. {rec}\n"
        
        md += "\n---\n*Report generated by Volatility3 IOC Extraction System*\n"
        return md