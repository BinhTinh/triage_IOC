from typing import List, Dict, Any, Optional
from collections import defaultdict
from src.models.timeline import Timeline, EventType
from src.models.attack_chain import AttackChain
from src.models.ioc import ValidatedIOC
from src.models.behavior import (
    BehaviorPattern, BehaviorMatch, MalwareClassification, MalwareFamily
)
from src.core.behavior_patterns import BEHAVIOR_PATTERNS

class BehaviorAnalyzer:
    def __init__(self):
        self.patterns = BEHAVIOR_PATTERNS
        self.matches: List[BehaviorMatch] = []
        
    def analyze(
        self, 
        timeline: Timeline, 
        attack_chain: AttackChain,
        validated_iocs: List[ValidatedIOC]
    ) -> MalwareClassification:
        
        self._match_patterns(timeline, attack_chain, validated_iocs)
        classification = self._classify_malware()
        
        return classification
    
    def _match_patterns(
        self, 
        timeline: Timeline, 
        attack_chain: AttackChain,
        validated_iocs: List[ValidatedIOC]
    ):
        for pattern in self.patterns:
            evidence = []
            match_score = 0.0
            
            for indicator in pattern.indicators:
                indicator_type, indicator_value = indicator.split(":", 1) if ":" in indicator else (indicator, "")
                
                matches = self._check_indicator(
                    indicator_type, 
                    indicator_value, 
                    timeline, 
                    attack_chain, 
                    validated_iocs
                )
                
                if matches:
                    evidence.extend(matches)
                    match_score += 1.0
            
            if evidence:
                confidence = (match_score / len(pattern.indicators)) * pattern.weight
                confidence = min(confidence, 1.0)
                
                self.matches.append(BehaviorMatch(
                    pattern=pattern,
                    confidence=confidence,
                    evidence=evidence
                ))
    
    def _check_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        timeline: Timeline,
        attack_chain: AttackChain,
        validated_iocs: List[ValidatedIOC]
    ) -> List[Dict[str, Any]]:
        
        matches = []
        
        if indicator_type == "file_access":
            for event in timeline.events:
                if event.event_type == EventType.FILE_ACCESS:
                    if indicator_value.lower() in event.description.lower():
                        matches.append({
                            "type": "file_access",
                            "description": event.description,
                            "timestamp": str(event.timestamp)
                        })
        
        elif indicator_type == "file_extension":
            for event in timeline.events:
                if event.event_type == EventType.FILE_ACCESS:
                    if indicator_value in event.description.lower():
                        matches.append({
                            "type": "file_extension",
                            "description": event.description
                        })
        
        elif indicator_type == "cmdline":
            for event in timeline.events:
                if event.event_type == EventType.PROCESS_CREATE:
                    cmdline = event.details.get("cmdline", "").lower()
                    if indicator_value.lower() in cmdline:
                        matches.append({
                            "type": "cmdline",
                            "process": event.details.get("process", ""),
                            "cmdline": cmdline[:100],
                            "pid": event.details.get("pid")
                        })
        
        elif indicator_type == "process":
            for event in timeline.events:
                if event.event_type == EventType.PROCESS_CREATE:
                    name = event.details.get("name", "").lower()
                    if indicator_value.lower() in name:
                        matches.append({
                            "type": "process",
                            "name": name,
                            "pid": event.details.get("pid")
                        })
        
        elif indicator_type == "injection":
            for event in timeline.events:
                if event.event_type == EventType.CODE_INJECTION:
                    process = event.details.get("process", "").lower()
                    if indicator_value.lower() in process:
                        matches.append({
                            "type": "injection",
                            "process": process,
                            "pid": event.details.get("pid"),
                            "address": event.details.get("address")
                        })
        
        elif indicator_type == "protection":
            for event in timeline.events:
                if event.event_type == EventType.CODE_INJECTION:
                    protection = event.details.get("protection", "")
                    if indicator_value in protection:
                        matches.append({
                            "type": "memory_protection",
                            "protection": protection,
                            "process": event.details.get("process")
                        })
        
        elif indicator_type == "network":
            network_events = [e for e in timeline.events if e.event_type == EventType.NETWORK_CONNECT]
            
            if "suspicious_port" in indicator_value:
                port = indicator_value.split(":")[1]
                for event in network_events:
                    if str(event.details.get("remote_port")) == port:
                        matches.append({
                            "type": "network",
                            "remote_ip": event.details.get("remote_ip"),
                            "remote_port": event.details.get("remote_port"),
                            "process": event.details.get("process")
                        })
            
            elif "external_ip" in indicator_value:
                for event in network_events:
                    ip = event.details.get("remote_ip", "")
                    if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                        matches.append({
                            "type": "network",
                            "remote_ip": ip,
                            "process": event.details.get("process")
                        })
        
        elif indicator_type == "path":
            for event in timeline.events:
                if event.event_type == EventType.FILE_ACCESS:
                    path = event.details.get("full_path", "").lower()
                    if indicator_value.lower() in path:
                        matches.append({
                            "type": "path",
                            "path": path
                        })

        elif indicator_type == "registry_persistence":
            for ioc in validated_iocs:
                if ioc.ioc.ioc_type == "registry_persistence":
                    if indicator_value.lower() in ioc.ioc.value.lower():
                        matches.append({
                            "type": "registry_persistence",
                            "key": ioc.ioc.value,
                            "data": ioc.ioc.context.get("data", ""),
                            "technique": ioc.ioc.context.get("technique", "")
                        })
        
        elif indicator_type == "registry_defense_evasion":
            for ioc in validated_iocs:
                if ioc.ioc.ioc_type == "registry_defense_evasion":
                    if indicator_value.lower() in ioc.ioc.value.lower():
                        matches.append({
                            "type": "registry_defense_evasion",
                            "key": ioc.ioc.value,
                            "severity": ioc.ioc.context.get("severity", "high")
                        })
        
        elif indicator_type == "registry_credential_access":
            for ioc in validated_iocs:
                if ioc.ioc.ioc_type == "registry_credential_access":
                    if indicator_value.lower() in ioc.ioc.value.lower():
                        matches.append({
                            "type": "registry_credential_access",
                            "key": ioc.ioc.value
                        })
        
        return matches
    
    def _classify_malware(self) -> MalwareClassification:
        if not self.matches:
            return MalwareClassification(
                primary_family=MalwareFamily.UNKNOWN,
                confidence=0.0,
                behavioral_summary="Insufficient behavioral indicators for classification"
            )
        
        family_scores = defaultdict(float)
        
        for match in self.matches:
            for family in match.pattern.malware_families:
                family_scores[family] += match.confidence
        
        sorted_families = sorted(family_scores.items(), key=lambda x: x[1], reverse=True)
        
        primary_family = sorted_families[0][0]
        primary_score = sorted_families[0][1]
        
        total_patterns = len(self.patterns)
        confidence = min(primary_score / (total_patterns * 0.3), 1.0)
        
        secondary_families = [f for f, score in sorted_families[1:4] if score > 0.3]
        
        capabilities = list(set(
            cap for match in self.matches 
            for cap in match.pattern.mitre_techniques
        ))
        
        behavioral_summary = self._generate_summary(primary_family, self.matches)
        
        return MalwareClassification(
            primary_family=primary_family,
            confidence=confidence,
            secondary_families=secondary_families,
            matched_patterns=self.matches,
            behavioral_summary=behavioral_summary,
            capabilities=capabilities
        )
    
    def _generate_summary(self, family: MalwareFamily, matches: List[BehaviorMatch]) -> str:
        summary_parts = []
        
        family_descriptions = {
            MalwareFamily.RANSOMWARE: "Ransomware characteristics detected with file encryption and system recovery deletion capabilities.",
            MalwareFamily.RAT: "Remote Access Trojan behavior identified with command & control and remote control features.",
            MalwareFamily.STEALER: "Information stealer detected targeting credentials, browser data, and sensitive files.",
            MalwareFamily.BANKER: "Banking trojan characteristics with credential theft and financial data targeting.",
            MalwareFamily.BACKDOOR: "Backdoor functionality detected enabling persistent remote access.",
            MalwareFamily.CRYPTOMINER: "Cryptocurrency mining activity with resource consumption patterns.",
            MalwareFamily.ROOTKIT: "Rootkit behavior with system-level hiding and stealth capabilities.",
            MalwareFamily.LOADER: "Loader/Dropper detected downloading and executing additional payloads.",
            MalwareFamily.DROPPER: "Dropper behavior installing additional malware components.",
            MalwareFamily.WORM: "Worm-like propagation mechanisms detected.",
            MalwareFamily.UNKNOWN: "Malicious activity detected but specific family classification unclear."
        }
        
        summary_parts.append(family_descriptions.get(family, "Malware detected."))
        summary_parts.append("")
        
        high_confidence = [m for m in matches if m.confidence > 0.7]
        if high_confidence:
            summary_parts.append("Key behaviors:")
            for match in high_confidence[:5]:
                summary_parts.append(f"  - {match.pattern.name} (confidence: {match.confidence:.0%})")
        
        return "\n".join(summary_parts)
