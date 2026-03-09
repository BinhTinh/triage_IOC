import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.models.case import Case
from src.models.ioc import ValidatedIOC
from src.config.settings import settings


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
    plugin_summary: Dict[str, Any] = field(default_factory=dict)


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
    
    @staticmethod
    def _to_datetime(value) -> datetime:
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value).replace("Z", "").split("+")[0])
    def _normalize_mitre_techniques(self, mitre_mapping: dict) -> List[dict]:
        techniques = mitre_mapping.get("techniques", {})
        if isinstance(techniques, dict):
            result = []
            for tid, data in techniques.items():
                tech_info = data.get("technique", {})
                result.append({
                    "id":              tid,
                    "name":            tech_info.get("name", "Unknown"),
                    "tactic":          tech_info.get("tactic", "Unknown"),
                    "ioc_count":       data.get("ioc_count", len(data.get("iocs", []))),
                    "recommendations": tech_info.get("recommendations", []),
                })
            return result
        return techniques if isinstance(techniques, list) else []

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

        malicious  = [i for i in validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in validated_iocs if i.verdict == "suspicious"]
        benign     = [i for i in validated_iocs if i.verdict == "benign"]

        threat_level, threat_score = self._calculate_threat_level(malicious, suspicious, mitre_mapping)

        has_external_validation = any(
            any(kw in (ioc.reason or "") for kw in ("VT:", "AbuseIPDB:", "DeepSeek"))
            for ioc in validated_iocs
        )

        now = datetime.now()
        try:
            started_str = self._to_datetime(case.created_at).isoformat() if case.created_at else "N/A"
        except Exception:
            started_str = str(case.created_at) if case.created_at else "N/A"

        try:
            duration_sec = (now - self._to_datetime(case.created_at)).total_seconds() if case.created_at else 0
            duration_str = f"{duration_sec:.0f} seconds ({duration_sec/60:.1f} min)"
        except Exception:
            duration_str = "N/A"

        injection_by_proc: Dict[str, list] = {}
        for ioc in malicious:
            if ioc.ioc.ioc_type == "injection":
                pid = ioc.ioc.context.get("pid", "?")
                proc = ioc.ioc.context.get("process", f"PID_{pid}")
                key = f"{proc} (PID {pid})"
                injection_by_proc.setdefault(key, []).append(ioc)

        with open(filepath, "w", encoding="utf-8") as f:

            f.write(f"{'#'*80}\n")
            f.write(f"#{'FORENSIC ANALYSIS SUMMARY REPORT':^78}#\n")
            f.write(f"{'#'*80}\n\n")

            if not has_external_validation:
                f.write(f"{'─'*80}\n")
                f.write(f"  ⚠  WARNING: External validation unavailable (no API keys configured)\n")
                f.write(f"     IOCs validated using local whitelist only — may contain false positives\n")
                f.write(f"{'─'*80}\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"CASE INFORMATION\n")
            f.write(f"{'='*80}\n")
            f.write(f"  Case ID:           {case.id}\n")
            f.write(f"  Dump Path:         {case.dump_path}\n")
            f.write(f"  Dump Hash:         {case.dump_hash}\n")
            f.write(f"  Operating System:  {case.os_type.upper()} {case.os_version} ({case.os_arch})\n")
            f.write(f"  Analysis Goal:     {case.goal}\n")
            f.write(f"  Analysis Started:  {started_str}\n")       
            f.write(f"  Report Generated:  {now.isoformat()}\n")
            f.write(f"  Duration:          {duration_str}\n\n")   

            f.write(f"{'='*80}\n")
            f.write(f"THREAT ASSESSMENT\n")
            f.write(f"{'='*80}\n\n")
            level_bar = self._generate_threat_bar(threat_level)
            f.write(f"  THREAT LEVEL:  {threat_level}\n")
            f.write(f"  THREAT SCORE:  {threat_score}/100\n")
            f.write(f"  {level_bar}\n\n")
            f.write(f"  Criteria:\n")
            f.write(f"    CRITICAL (80-100): Active compromise, immediate action required\n")
            f.write(f"    HIGH     (60-79):  Confirmed malicious activity detected\n")
            f.write(f"    MEDIUM   (40-59):  Suspicious indicators requiring investigation\n")
            f.write(f"    LOW      (0-39):   Minimal indicators, likely clean\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"KEY FINDINGS\n")
            f.write(f"{'='*80}\n\n")

            finding_idx = 1
            if injection_by_proc:
                total_inj = sum(len(v) for v in injection_by_proc.values())
                proc_list = ", ".join(injection_by_proc.keys())
                f.write(f"  [{finding_idx}] PROCESS INJECTION DETECTED (T1055)\n")
                f.write(f"      {total_inj} injected memory regions across {len(injection_by_proc)} process(es):\n")
                f.write(f"      {proc_list}\n\n")
                finding_idx += 1

            vt_hits = [i for i in suspicious if "VT:" in (i.reason or "")]
            network_malicious = [i for i in malicious if i.ioc.ioc_type in ("ipv4", "ip")]
            if network_malicious:
                rare_port_iocs = [i for i in network_malicious if "rare_port" in i.ioc.context.get("reasons", [])]
                beaconing_iocs = [i for i in network_malicious if i.ioc.context.get("beaconing")]
                if rare_port_iocs or beaconing_iocs:
                    f.write(f" [{finding_idx}] MALICIOUS NETWORK CONNECTIONS DETECTED (T1071)\n")
                    if rare_port_iocs:
                        for ioc in rare_port_iocs[:5]:
                            ctx = ioc.ioc.context
                            f.write(f"   {ioc.ioc.value}:{ctx.get('remote_port','?')} "
                                    f"[{ctx.get('process','?')}] via {ioc.ioc.source_plugin}\n")
                    if beaconing_iocs:
                        f.write(f"   Beaconing pattern: {len(beaconing_iocs)} IP(s) with repeated connections\n")
                    f.write("\n")
                    finding_idx += 1
            for ioc in vt_hits:
                f.write(f"  [{finding_idx}] KNOWN MALICIOUS HASH\n")
                f.write(f"      SHA256: {ioc.ioc.value}\n")
                f.write(f"      Verdict: {ioc.reason}\n\n")
                finding_idx += 1

            import re
            for proc_key, iocs in injection_by_proc.items():
                proc_name = iocs[0].ioc.context.get("process", "")
                if re.match(r'^[a-fA-F0-9]{8,}$', proc_name):
                    f.write(f"  [{finding_idx}] OBFUSCATED PROCESS NAME (T1036 Masquerading)\n")
                    f.write(f"      Process '{proc_name}' uses hex string as name\n\n")
                    finding_idx += 1

            if finding_idx == 1:
                f.write(f"  No significant findings.\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"IOC SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"  Total IOCs Extracted:    {len(validated_iocs)}\n")
            f.write(f"  ├── Malicious:           {len(malicious)}"
                    f"{' ⚠  ALERT' if malicious else ''}\n")
            f.write(f"  ├── Suspicious:          {len(suspicious)}\n")
            f.write(f"  └── Benign:              {len(benign)}\n\n")

            by_type: Dict[str, int] = {}
            for ioc in validated_iocs:
                by_type[ioc.ioc.ioc_type] = by_type.get(ioc.ioc.ioc_type, 0) + 1
            f.write(f"  By Type:\n")
            for ioc_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
                f.write(f"    - {ioc_type}: {count}\n")
            f.write("\n")

            if malicious:
                f.write(f"{'='*80}\n")
                f.write(f"MALICIOUS INDICATORS (CRITICAL FINDINGS)\n")
                f.write(f"{'='*80}\n\n")

                if injection_by_proc:
                    f.write(f"  Process Injection Summary:\n")
                    f.write(f"  {'─'*60}\n")
                    for proc_key, iocs in injection_by_proc.items():
                        sample_ctx = iocs[0].ioc.context
                        f.write(f"  Process : {sample_ctx.get('process', '?')}\n")
                        f.write(f"  PID     : {sample_ctx.get('pid', '?')}\n")
                        f.write(f"  Regions : {len(iocs)} injected memory region(s)\n")
                        f.write(f"  Protect : {sample_ctx.get('protection', 'N/A')}\n")
                        f.write(f"  MITRE   : T1055 - Process Injection\n")
                        f.write(f"  Addresses:\n")
                        for ioc in iocs:
                            f.write(f"    - {ioc.ioc.value}\n")
                        f.write("\n")

                non_inj = [i for i in malicious if i.ioc.ioc_type != "injection"]
                if non_inj:
                    for i, ioc in enumerate(non_inj[:20], 1):
                        f.write(f"  [{i}] {ioc.ioc.ioc_type.upper()}: {ioc.ioc.value}\n")
                        f.write(f"      Confidence: {ioc.final_confidence:.0%}\n")
                        f.write(f"      Source:     {ioc.ioc.source_plugin}\n")
                        f.write(f"      Reason:     {ioc.reason}\n")
                        if ioc.ioc.context.get("technique"):
                            f.write(f"      MITRE:      {ioc.ioc.context['technique']}\n")
                        f.write("\n")
                    if len(non_inj) > 20:
                        f.write(f"  ... and {len(non_inj) - 20} more malicious indicators\n\n")

            if suspicious:
                f.write(f"{'='*80}\n")
                f.write(f"SUSPICIOUS INDICATORS (REQUIRES INVESTIGATION)\n")
                f.write(f"{'='*80}\n\n")
                for i, ioc in enumerate(suspicious[:10], 1):
                    f.write(f"  [{i}] {ioc.ioc.ioc_type.upper()}: {ioc.ioc.value}\n")
                    f.write(f"      Confidence: {ioc.final_confidence:.0%}\n")
                    f.write(f"      Source:     {ioc.ioc.source_plugin}\n")
                    f.write(f"      Reason:     {ioc.reason or 'No validation data'}\n\n")
                if len(suspicious) > 10:
                    f.write(f"  ... and {len(suspicious) - 10} more suspicious indicators\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"TIMELINE SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            if case.timeline:
                tl = case.timeline
                f.write(f"  Total Events: {tl.total_events}\n")
                f.write(f"  Time Range:   {tl.start_time} → {tl.end_time}\n\n")
                f.write(f"  Event Types:\n")
                for event_type, count in sorted(tl.event_types.items(), key=lambda x: -x[1]):
                    f.write(f"    - {event_type}: {count}\n")
                f.write("\n")
                try:
                    from src.models.timeline import EventSeverity
                    high_events = tl.get_events_by_severity(EventSeverity.HIGH)
                    if high_events:
                        f.write(f"  High Severity Events (top 10):\n")
                        for event in high_events[:10]:
                            f.write(f"    [{event.timestamp}] {event.description}\n")
                        f.write("\n")
                except Exception:
                    pass
            else:
                f.write(f"  Timeline not available\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"ATTACK CHAIN SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            if hasattr(case, 'attack_chain') and case.attack_chain:
                chain = case.attack_chain
                f.write(f"  Initial Vector: {chain.initial_vector or 'Unknown'}\n")
                f.write(f"  Entry Point:    PID {chain.entry_point_pid or 'Unknown'}\n")
                f.write(f"  Attack Stages:  {len(chain.stages)}\n")
                f.write(f"  Confidence:     {chain.confidence:.0%}\n\n")
                if chain.stages:
                    f.write(f"  Attack Progression:\n")
                    try:
                        sorted_stages = sorted(
                            chain.stages.items(),
                            key=lambda x: x[1].timestamp if x[1].timestamp else datetime.max
                        )
                        for stage_enum, stage_info in sorted_stages:
                            time_str = stage_info.timestamp.strftime("%H:%M:%S") if stage_info.timestamp else "N/A"
                            f.write(f"    [{time_str}] {stage_enum.value.replace('_', ' ').title()}\n")
                    except Exception as e:
                        f.write(f"    (Error rendering stages: {e})\n")
                    f.write("\n")
            else:
                f.write(f"  Attack chain not available\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"MALWARE CLASSIFICATION\n")
            f.write(f"{'='*80}\n\n")
            if hasattr(case, 'malware_classification') and case.malware_classification:
                clf = case.malware_classification
                f.write(f"  Primary Family:   {clf.primary_family.value.upper().replace('_', ' ')}\n")
                f.write(f"  Confidence:       {clf.confidence:.0%}\n")
                if clf.secondary_families:
                    f.write(f"  Secondary:        {', '.join(fam.value.replace('_',' ').title() for fam in clf.secondary_families)}\n")
                f.write(f"  Matched Patterns: {len(clf.matched_patterns)}\n")
                f.write(f"  Capabilities:     {len(clf.capabilities)} MITRE techniques\n\n")
                high_conf = [m for m in clf.matched_patterns if m.confidence > 0.7]
                if high_conf:
                    f.write(f"  High Confidence Behaviors:\n")
                    for match in high_conf[:5]:
                        f.write(f"    - {match.pattern.name} ({match.confidence:.0%})\n")
                    f.write("\n")
            else:
                f.write(f"  Malware classification not available\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"MITRE ATT&CK MAPPING\n")
            f.write(f"{'='*80}\n\n")
            techniques = self._normalize_mitre_techniques(mitre_mapping)
            if techniques:
                f.write(f"  Detected Techniques: {len(techniques)}\n\n")
                tactics_grouped: Dict[str, list] = {}
                for tech in techniques:
                    tactic = tech.get("tactic", "Unknown")
                    tactics_grouped.setdefault(tactic, []).append(tech)
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
            failed_plugins     = len(plugin_results) - successful_plugins
            f.write(f"  Total Plugins: {len(plugin_results)}\n")
            f.write(f"  ├── Successful: {successful_plugins}\n")
            f.write(f"  └── Failed:     {failed_plugins}\n\n")
            f.write(f"  Plugin Details:\n")
            for plugin_name, result in plugin_results.items():
                status = "✓" if result.get("success", False) else "✗"
                rows   = result.get("rows", 0)
                err    = f" [{result['error'][:40]}]" if not result.get("success") and result.get("error") else ""
                f.write(f"    [{status}] {plugin_name}: {rows} rows{err}\n")
            f.write("\n")

            f.write(f"{'='*80}\n")
            f.write(f"RECOMMENDATIONS\n")
            f.write(f"{'='*80}\n\n")
            recommendations = self._generate_recommendations(malicious, suspicious, mitre_mapping, threat_level)
            for i, rec in enumerate(recommendations, 1):
                f.write(f"  {i}. {rec}\n")
            f.write("\n")

            f.write(f"{'='*80}\n")
            f.write(f"VISUALIZATIONS\n")
            f.write(f"{'='*80}\n\n")
            if hasattr(case, 'timeline') and case.timeline:
                try:
                    stats_chart = TextVisualizer.generate_statistics_chart(case.timeline, validated_iocs)
                    f.write(stats_chart)
                    f.write("\n\n")
                except Exception as e:
                    f.write(f"  (Chart generation failed: {e})\n\n")
            f.write(f"  See attack_chain.txt for process tree and attack flow diagrams.\n")
            f.write(f"  See narrative.txt for detailed attack story.\n\n")

            f.write(f"{'='*80}\n")
            f.write(f"FILES IN THIS REPORT\n")
            f.write(f"{'='*80}\n\n")
            case_name = self.case_dir.name if self.case_dir else "CASE"
            f.write(f"  {case_name}/\n")
            f.write(f"  ├── SUMMARY.txt            (This file)\n")
            f.write(f"  ├── SUMMARY.md             (Markdown version)\n")
            f.write(f"  ├── narrative.txt          (Detailed attack story)\n")
            f.write(f"  ├── timeline.txt / .json   (Chronological events)\n")
            f.write(f"  ├── attack_chain.txt / .json\n")
            f.write(f"  ├── behavior_analysis.txt / .json\n")
            f.write(f"  ├── visualizations.txt\n")
            f.write(f"  ├── iocs.json\n")
            f.write(f"  └── plugins/               (Raw Volatility outputs)\n")
            plugins_dir = self.case_dir / "plugins"
            if plugins_dir.exists():
                plugin_files = sorted(plugins_dir.glob("*.txt"))
                for pf in list(plugin_files)[:3]:
                    f.write(f"      ├── {pf.name}\n")
                f.write(f"      └── ... ({len(list(plugin_files))} plugin outputs)\n")
            f.write(f"\n{'='*80}\n")
            f.write(f"END OF REPORT\n")
            f.write(f"{'='*80}\n")

        return str(filepath)

    
    def _calculate_threat_level(self, malicious, suspicious, mitre_mapping) -> tuple:
        if not malicious and not suspicious:
            return "LOW", 0

        malicious_score  = sum(i.final_confidence for i in malicious) * 10 
        suspicious_score = sum(i.final_confidence for i in suspicious) * 3  

        base_score = malicious_score + suspicious_score

        techniques       = self._normalize_mitre_techniques(mitre_mapping)
        tech_multiplier  = 1 + (min(len(techniques), 5) * 0.05) 

        critical_techniques = {"T1055", "T1059.001", "T1105", "T1071"}
        critical_count   = sum(1 for t in techniques if t.get("id") in critical_techniques)
        critical_bonus   = critical_count * 5

        injection_iocs = [i for i in malicious if i.ioc.ioc_type == "injection"]
        injection_bonus = min(len(injection_iocs) * 2, 10)

        network_iocs = [i for i in malicious if i.ioc.ioc_type in ("ipv4", "ip")]
        rare_port_bonus = min(
            sum(5 for i in network_iocs if "rare_port" in i.ioc.context.get("reasons", [])), 15
        )
        beaconing_bonus = min(
            sum(3 for i in network_iocs if i.ioc.context.get("beaconing")), 10
        )

        score = (base_score * tech_multiplier) + critical_bonus + injection_bonus + rare_port_bonus + beaconing_bonus
        score = min(100, max(0, int(score)))

        if score >= 80:   level = "CRITICAL"
        elif score >= 60: level = "HIGH"
        elif score >= 40: level = "MEDIUM"
        else:             level = "LOW"

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
        
        malicious_ips = [i.ioc.value for i in malicious if i.ioc.ioc_type in ("ip", "ipv4")]
        if malicious_ips:
            recommendations.append(f"[HIGH] Block malicious IPs at firewall: {', '.join(malicious_ips[:5])}")

        beaconing_iocs = [i for i in malicious if i.ioc.context.get("beaconing")]
        if beaconing_iocs:
            beacon_ips = list({i.ioc.value for i in beaconing_iocs})
            recommendations.append(
                f"[HIGH] Beaconing detected to {len(beacon_ips)} IP(s) — "
                f"investigate C2 channel: {', '.join(beacon_ips[:3])}"
            )

        rare_port_iocs = [i for i in malicious if "rare_port" in i.ioc.context.get("reasons", [])]
        if rare_port_iocs:
            ports = list({i.ioc.context.get("remote_port") for i in rare_port_iocs})
            recommendations.append(
                f"[HIGH] Suspicious ports detected: {ports[:5]} — common C2/RAT/Tor ports"
            )

        malicious_domains = [i.ioc.value for i in malicious if i.ioc.ioc_type == "domain"]
        if malicious_domains:
            recommendations.append(f"[HIGH] Block malicious domains in DNS/proxy: {', '.join(malicious_domains[:5])}")
        
        malicious_hashes = [i.ioc.value for i in malicious if i.ioc.ioc_type in ["md5", "sha1", "sha256"]]
        if malicious_hashes:
            recommendations.append("[HIGH] Add file hashes to EDR/AV blocklist")
        
        injections = [i for i in malicious if i.ioc.ioc_type == "injection"]
        if injections:
            recommendations.append("[HIGH] Investigate process injection - possible active malware")
        
        for tech in self._normalize_mitre_techniques(mitre_mapping)[:3]:
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
        mitre_mapping: dict,
        plugin_results: Optional[Dict[str, dict]] = None,
    ) -> ForensicReport:

        malicious = [i for i in validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in validated_iocs if i.verdict == "suspicious"]
        
        threat_level, threat_score = self._calculate_threat_level(malicious, suspicious, mitre_mapping)
        recommendations = self._generate_recommendations(malicious, suspicious, mitre_mapping, threat_level)
        techniques = self._normalize_mitre_techniques(mitre_mapping)

        plugin_summary: Dict[str, Any] = {}
        if plugin_results:
            plugin_summary = {
                "total":      len(plugin_results),
                "successful": sum(1 for r in plugin_results.values() if r.get("success")),
                "failed":     sum(1 for r in plugin_results.values() if not r.get("success")),
                "details": {
                    name: {"success": r.get("success"), "rows": r.get("rows", 0)}
                    for name, r in plugin_results.items()
                },
            }

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
                "techniques_detected": len(techniques),
                "analysis_duration_minutes": int((datetime.now() - self._to_datetime(case.created_at)).total_seconds() // 60)
            },
            iocs={
                "malicious": [self._ioc_to_dict(i) for i in malicious],
                "suspicious": [self._ioc_to_dict(i) for i in suspicious[:20]]
            },
            mitre=mitre_mapping,
            recommendations=recommendations,
            timeline=timeline,
            plugin_summary=plugin_summary,
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
    
    def save_markdown(self, report: ForensicReport) -> str:
        if not self.case_dir:
            raise ValueError("Case directory not created.")

        report_path = self.case_dir / "SUMMARY.md"

        with open(report_path, 'w') as f:
            f.write(self._generate_markdown(report))

        plugins_dir = self.case_dir / "plugins"
        if plugins_dir.exists():
            plugin_files = list(plugins_dir.glob("*.txt")) + list(plugins_dir.glob("*.json"))
            if plugin_files:
                with open(report_path, 'a', encoding='utf-8') as f:
                    f.write("\n\n---\n## Plugin Outputs\n\n")
                    for plugin_file in sorted(plugin_files):
                        f.write(f"- {plugin_file.name}\n")

        return str(report_path)
    
    def _generate_markdown(self, report: ForensicReport) -> str:
        level_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            report.summary['threat_level'], "⚪"
        )

        malicious_iocs  = report.iocs.get("malicious", [])
        suspicious_iocs = report.iocs.get("suspicious", [])

        injection_by_proc: dict = {}
        non_injection_malicious: list = []
        for ioc in malicious_iocs:
            if ioc['type'] == 'injection':
                ctx  = ioc.get('context', {})
                proc = ctx.get('process', 'unknown')
                pid  = ctx.get('pid', '?')
                key  = f"{proc} (PID {pid})"
                injection_by_proc.setdefault(key, []).append(ioc)
            else:
                non_injection_malicious.append(ioc)

        key_findings = []

        if injection_by_proc:
            total_inj = sum(len(v) for v in injection_by_proc.values())
            procs     = list(injection_by_proc.keys())
            key_findings.append(
                f"**{total_inj} memory injection regions** detected across "
                f"{len(procs)} process(es): `{'`, `'.join(procs)}` — "
                f"all marked `PAGE_EXECUTE_READWRITE` (T1055 Process Injection)"
            )

        vt_hits = [i for i in suspicious_iocs if "VT:" in i.get('reason', '')]
        for ioc in vt_hits:
            reason = ioc.get('reason', '')
            key_findings.append(
                f"**SHA256 hash `{ioc['value'][:16]}...`** flagged by VirusTotal: "
                f"{reason} — high confidence malware sample"
            )

        hex_procs = [k for k in injection_by_proc if any(
            c.isdigit() or c in 'abcdef' for c in k.lower().split('(')[0].strip()
            ) and '.' not in k.split('(')[0]]
        if hex_procs:
            key_findings.append(
                f"**Obfuscated process name** detected: `{'`, `'.join(hex_procs)}` — "
                f"hex string used as process name indicates active evasion (T1036 Masquerading)"
            )

        suspicious_filepath = [i for i in suspicious_iocs if i['type'] == 'filepath'
                            and i['value'] not in ('C:\\\\', 'c:\\\\', 'E:\\\\', 'e:\\\\')]
        if suspicious_filepath:
            key_findings.append(
                f"**Suspicious file paths** found in process command lines"
            )

        md = f"""# 🔍 Forensic Analysis Report

    ## Case Information

    | Field | Value |
    |-------|-------|
    | **Case ID** | `{report.case_id}` |
    | **Generated** | {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')} |
    | **OS** | {report.os_type.upper()} {report.os_version} |
    | **Dump Hash** | `{report.summary.get('dump_hash', 'N/A')}` |

    ---

    ## {level_emoji} Threat Assessment

    | Metric | Value |
    |--------|-------|
    | **Threat Level** | {level_emoji} **{report.summary['threat_level']}** |
    | **Threat Score** | **{report.summary['threat_score']}/100** |
    | **Total IOCs** | {report.summary['total_iocs']} |
    | **Malicious** | 🔴 {report.summary['malicious']} |
    | **Suspicious** | 🟡 {report.summary['suspicious']} |
    | **ATT&CK Techniques** | {report.summary['techniques_detected']} |

    ---

    ## 📌 Key Findings

    """
        if key_findings:
            for i, finding in enumerate(key_findings, 1):
                md += f"{i}. {finding}\n"
        else:
            md += "_No significant findings — system appears clean._\n"
        if malicious_iocs:
            md += "\n---\n\n## 🚨 Malicious Indicators\n\n"

            if injection_by_proc:
                md += f"### Process Injection (T1055) — {sum(len(v) for v in injection_by_proc.values())} regions\n\n"
                md += "| Process | PID | Injected Regions | Protection | Confidence |\n"
                md += "|---------|-----|-----------------|------------|------------|\n"
                for proc_key, iocs in injection_by_proc.items():
                    sample_ctx = iocs[0].get('context', {})
                    md += (f"| `{sample_ctx.get('process', '?')}` "
                        f"| {sample_ctx.get('pid', '?')} "
                        f"| **{len(iocs)}** regions "
                        f"| `{sample_ctx.get('protection', 'N/A')}` "
                        f"| {iocs[0]['confidence']:.0%} |\n")
                md += "\n"
                for proc_key, iocs in injection_by_proc.items():
                    proc_name = iocs[0].get('context', {}).get('process', '')
                    import re
                    if re.match(r'^[a-fA-F0-9]{8,}$', proc_name):
                        md += f"> ⚠️ **`{proc_name}`** — process name is a hex string, "
                        md += f"strong indicator of masquerading malware (T1036)\n\n"

            if non_injection_malicious:
                md += "### Other Malicious IOCs\n\n"
                md += "| Type | Value | Confidence | Source | Reason |\n"
                md += "|------|-------|------------|--------|--------|\n"
                for ioc in non_injection_malicious:
                    value = ioc['value'][:60] + "..." if len(ioc['value']) > 60 else ioc['value']
                    md += (f"| `{ioc['type']}` | `{value}` "
                        f"| {ioc['confidence']:.0%} "
                        f"| {ioc['source']} "
                        f"| {ioc.get('reason', 'N/A')[:60]} |\n")
                md += "\n"

        if suspicious_iocs:
            md += "---\n\n## ⚠️ Suspicious Indicators\n\n"
            md += "| Type | Value | Confidence | Reason |\n"
            md += "|------|-------|------------|--------|\n"
            for ioc in suspicious_iocs:
                value = ioc['value'][:70] + "..." if len(ioc['value']) > 70 else ioc['value']
                reason = ioc.get('reason', 'No validation data')
                if "VT:" in reason:
                    reason = f"**{reason}**"
                md += f"| `{ioc['type']}` | `{value}` | {ioc['confidence']:.0%} | {reason} |\n"
            md += "\n"

        techniques = report.mitre.get("techniques", [])
        if techniques:
            md += "---\n\n## 🗺️ MITRE ATT&CK Coverage\n\n"
            md += "| ID | Technique | Tactic | IOC Count | Top Recommendation |\n"
            md += "|----|-----------|--------|-----------|--------------------|\n"
            for tech in techniques:
                if isinstance(tech, dict):
                    rec = tech.get('recommendations', ['N/A'])[0] if tech.get('recommendations') else 'N/A'
                    tid = tech.get('id', '')
                    url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
                    md += (f"| [{tid}]({url}) "
                        f"| {tech.get('name', 'N/A')} "
                        f"| {tech.get('tactic', 'N/A')} "
                        f"| {tech.get('ioc_count', 0)} "
                        f"| {rec[:60]} |\n")
            md += "\n"

        md += "---\n\n## 🛡️ Recommendations\n\n"
        priority_icon = {"[IMMEDIATE]": "🚨", "[HIGH]": "🔴", "[MEDIUM]": "🟡", "[STANDARD]": "🔵"}
        for i, rec in enumerate(report.recommendations, 1):
            icon = next((v for k, v in priority_icon.items() if rec.startswith(k)), "•")
            md += f"{i}. {icon} {rec}\n"

        md += "\n---\n*Report generated by Volatility3 IOC Extraction System*\n"
        return md
