from datetime import datetime
from typing import List, Dict, Any, Optional
from src.models.timeline import Timeline, EventType
from src.models.attack_chain import AttackChain, AttackStage
from src.models.behavior import MalwareClassification, MalwareFamily
from src.models.ioc import ValidatedIOC

class NarrativeGenerator:
    def __init__(self):
        self.narrative_parts = []
        self.validated_iocs = []
        
    def generate_full_narrative(
        self,
        timeline: Timeline,
        attack_chain: AttackChain,
        classification: MalwareClassification,
        validated_iocs: List[ValidatedIOC]
    ) -> str:
        
        self.narrative_parts = []
        self.validated_iocs = validated_iocs
        
        self._add_executive_summary(classification, attack_chain, timeline)
        self._add_attack_timeline(timeline, attack_chain)
        self._add_technical_details()
        self._add_impact_assessment(classification, attack_chain)
        self._add_recommendations(classification)
        
        return "\n\n".join(self.narrative_parts)
    
    def _add_executive_summary(
        self,
        classification: MalwareClassification,
        attack_chain: AttackChain,
        timeline: Timeline
    ):
        summary = []
        summary.append("="*80)
        summary.append("EXECUTIVE SUMMARY")
        summary.append("="*80)
        summary.append("")
        
        family_name = classification.primary_family.value.replace("_", " ").title()
        confidence_desc = "high" if classification.confidence > 0.8 else "moderate" if classification.confidence > 0.6 else "low"
        
        summary.append(f"This memory forensics analysis reveals evidence of {family_name} malware ")
        summary.append(f"with {confidence_desc} confidence ({classification.confidence:.0%}). ")
        
        if attack_chain.stages:
            summary.append(f"The attack progressed through {len(attack_chain.stages)} distinct stages, ")
            summary.append(f"spanning {timeline.total_events} recorded events.")
        
        summary.append("")
        
        if classification.primary_family == MalwareFamily.RANSOMWARE:
            summary.append("KEY FINDINGS: File encryption activity detected with evidence of shadow copy ")
            summary.append("deletion and system recovery sabotage. This indicates an active ransomware ")
            summary.append("attack attempting to prevent file recovery.")
        
        elif classification.primary_family == MalwareFamily.RAT:
            summary.append("KEY FINDINGS: Remote Access Trojan capabilities identified including command ")
            summary.append("and control communication, process injection, and potential keylogging. ")
            summary.append("This represents a persistent threat with full system compromise.")
        
        elif classification.primary_family == MalwareFamily.STEALER:
            summary.append("KEY FINDINGS: Information stealing behavior detected targeting credentials, ")
            summary.append("browser data, and sensitive files. Data exfiltration mechanisms observed.")
        
        elif classification.primary_family == MalwareFamily.BACKDOOR:
            summary.append("KEY FINDINGS: Backdoor functionality detected providing unauthorized remote ")
            summary.append("access. Persistent mechanisms and privilege escalation attempts identified.")
        
        else:
            summary.append("KEY FINDINGS: Malicious activity detected with multiple suspicious behaviors ")
            summary.append("and indicators of compromise throughout the system.")
        
        summary.append("")
        
        malicious_count = len([ioc for ioc in self.validated_iocs if ioc.verdict == "malicious"])
        if malicious_count > 0:
            summary.append(f"THREAT LEVEL: CRITICAL - {malicious_count} confirmed malicious indicators")
        else:
            summary.append(f"THREAT LEVEL: HIGH - Suspicious activity requires immediate investigation")
        
        self.narrative_parts.append("\n".join(summary))
    
    def _add_attack_timeline(self, timeline: Timeline, attack_chain: AttackChain):
        narrative = []
        narrative.append("="*80)
        narrative.append("ATTACK NARRATIVE & TIMELINE")
        narrative.append("="*80)
        narrative.append("")
        
        if attack_chain.initial_vector:
            narrative.append(f"INITIAL ACCESS: The attack began through {attack_chain.initial_vector}")
            if attack_chain.entry_point_pid:
                narrative.append(f"(PID {attack_chain.entry_point_pid}). ")
        
        narrative.append("")
        narrative.append("ATTACK PROGRESSION:")
        narrative.append("")
        
        sorted_stages = sorted(
            attack_chain.stages.items(),
            key=lambda x: x[1].timestamp if x[1].timestamp else datetime.max
        )
        
        for i, (stage_enum, stage_info) in enumerate(sorted_stages, 1):
            time_str = stage_info.timestamp.strftime("%Y-%m-%d %H:%M:%S") if stage_info.timestamp else "Unknown time"
            
            narrative.append(f"[{i}] {stage_enum.value.upper().replace('_', ' ')} - {time_str}")
            narrative.append(f"    └─ {stage_info.description}")
            
            if stage_info.techniques:
                narrative.append(f"    └─ Techniques: {', '.join(stage_info.techniques)}")
            
            narrative.append("")
        
        high_severity = [e for e in timeline.events if e.severity.value in ["high", "critical"]]
        if high_severity:
            narrative.append("CRITICAL EVENTS:")
            narrative.append("")
            
            for event in high_severity[:10]:
                time_str = event.timestamp.strftime("%H:%M:%S") if event.timestamp and event.timestamp.year > 2000 else "N/A"
                narrative.append(f"  [{time_str}] {event.description}")
            
            if len(high_severity) > 10:
                narrative.append(f"  ... and {len(high_severity) - 10} more critical events")
        
        self.narrative_parts.append("\n".join(narrative))
    
    def _add_technical_details(self):
        details = []
        details.append("="*80)
        details.append("TECHNICAL ANALYSIS")
        details.append("="*80)
        details.append("")
        
        malicious = [ioc for ioc in self.validated_iocs if ioc.verdict == "malicious"]
        
        if malicious:
            details.append("CONFIRMED MALICIOUS INDICATORS:")
            details.append("")
            
            injections = [ioc for ioc in malicious if ioc.ioc.ioc_type == "injection"]
            if injections:
                details.append(f"Process Injection Detected ({len(injections)} instances):")
                for ioc in injections[:5]:
                    pid = ioc.ioc.context.get("pid")
                    process = ioc.ioc.context.get("process", "unknown")
                    details.append(f"  • PID {pid} ({process}) - Code injection at memory address {ioc.ioc.value}")
                details.append("")
            
            hashes = [ioc for ioc in malicious if ioc.ioc.ioc_type in ["md5", "sha1", "sha256"]]
            if hashes:
                details.append(f"Malicious File Hashes ({len(hashes)}):")
                for ioc in hashes[:5]:
                    details.append(f"  • {ioc.ioc.ioc_type.upper()}: {ioc.ioc.value}")
                    if ioc.reason:
                        details.append(f"    Reason: {ioc.reason[:100]}")
                details.append("")
            
            ips = [ioc for ioc in malicious if ioc.ioc.ioc_type == "ipv4"]
            if ips:
                details.append(f"Malicious Network Indicators ({len(ips)}):")
                for ioc in ips:
                    details.append(f"  • IP: {ioc.ioc.value}")
                    port = ioc.ioc.context.get("remote_port")
                    if port:
                        details.append(f"    Port: {port}")
                details.append("")
        
        details.append("BEHAVIORAL INDICATORS:")
        details.append("Multiple suspicious behaviors correlate to known malware patterns.")
        details.append("See Behavior Analysis section for detailed pattern matching results.")
        
        self.narrative_parts.append("\n".join(details))
    
    def _add_impact_assessment(
        self,
        classification: MalwareClassification,
        attack_chain: AttackChain
    ):
        impact = []
        impact.append("="*80)
        impact.append("IMPACT ASSESSMENT")
        impact.append("="*80)
        impact.append("")
        
        if classification.primary_family == MalwareFamily.RANSOMWARE:
            impact.append("SEVERITY: CRITICAL")
            impact.append("")
            impact.append("• Data Loss Risk: HIGH - File encryption detected")
            impact.append("• System Recovery: COMPROMISED - Shadow copies deleted")
            impact.append("• Business Impact: SEVERE - Potential ransomware payment demand")
            impact.append("• Data Availability: AT RISK - Files may be encrypted")
        
        elif classification.primary_family == MalwareFamily.RAT:
            impact.append("SEVERITY: CRITICAL")
            impact.append("")
            impact.append("• System Control: COMPROMISED - Remote access established")
            impact.append("• Data Confidentiality: BREACHED - Full system access")
            impact.append("• Persistence: CONFIRMED - Attacker maintains access")
            impact.append("• Lateral Movement Risk: HIGH - May spread to other systems")
        
        elif classification.primary_family == MalwareFamily.STEALER:
            impact.append("SEVERITY: HIGH")
            impact.append("")
            impact.append("• Credential Theft: CONFIRMED - Passwords compromised")
            impact.append("• Data Confidentiality: BREACHED - Sensitive data stolen")
            impact.append("• Account Security: AT RISK - Credentials may be sold/used")
            impact.append("• Identity Theft Risk: ELEVATED")
        
        else:
            impact.append("SEVERITY: HIGH")
            impact.append("")
            impact.append("• System Integrity: COMPROMISED")
            impact.append("• Security Posture: DEGRADED")
            impact.append("• Data Confidentiality: AT RISK")
            impact.append("• Further Investigation: REQUIRED")
        
        impact.append("")
        
        malicious_processes = sum(1 for node in self._flatten_process_tree(attack_chain.process_tree) if node.is_malicious)
        if malicious_processes > 0:
            impact.append(f"AFFECTED PROCESSES: {malicious_processes} confirmed malicious")
        
        self.narrative_parts.append("\n".join(impact))
    
    def _add_recommendations(self, classification: MalwareClassification):
        recs = []
        recs.append("="*80)
        recs.append("RECOMMENDED ACTIONS")
        recs.append("="*80)
        recs.append("")
        
        recs.append("IMMEDIATE ACTIONS (Within 1 hour):")
        recs.append("  1. Isolate affected system from network immediately")
        recs.append("  2. Disable network adapters and wireless connections")
        recs.append("  3. Preserve memory dump and disk images for forensics")
        recs.append("  4. Document all observable indicators and timestamps")
        recs.append("  5. Notify incident response team and management")
        recs.append("")
        
        if classification.primary_family == MalwareFamily.RANSOMWARE:
            recs.append("RANSOMWARE-SPECIFIC ACTIONS:")
            recs.append("  • DO NOT pay ransom - No guarantee of file recovery")
            recs.append("  • Check backup systems immediately - May be compromised")
            recs.append("  • Scan other systems for lateral movement")
            recs.append("  • Attempt file recovery from shadow copies if available")
            recs.append("")
        
        elif classification.primary_family == MalwareFamily.STEALER:
            recs.append("CREDENTIAL THEFT RESPONSE:")
            recs.append("  • Force password reset for all user accounts")
            recs.append("  • Revoke all active sessions and tokens")
            recs.append("  • Review recent account activity for suspicious logins")
            recs.append("  • Enable multi-factor authentication on all accounts")
            recs.append("")
        
        recs.append("SHORT-TERM ACTIONS (Within 24 hours):")
        recs.append("  1. Conduct full malware scan on all network systems")
        recs.append("  2. Review firewall and IDS logs for C2 communication")
        recs.append("  3. Block identified malicious IPs/domains at perimeter")
        recs.append("  4. Update antivirus signatures and security tools")
        recs.append("  5. Initiate full forensic investigation")
        recs.append("")
        
        recs.append("LONG-TERM REMEDIATION:")
        recs.append("  • Rebuild compromised system from clean backup")
        recs.append("  • Implement application whitelisting")
        recs.append("  • Enhanced monitoring and threat hunting")
        recs.append("  • Security awareness training for users")
        recs.append("  • Review and update incident response procedures")
        
        self.narrative_parts.append("\n".join(recs))
    
    def _flatten_process_tree(self, nodes: list) -> list:
        result = []
        for node in nodes:
            result.append(node)
            result.extend(self._flatten_process_tree(node.children))
        return result
