from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict
from src.models.timeline import Timeline, TimelineEvent, EventType
from src.models.attack_chain import (
    AttackChain, AttackStage, KillChainStage, 
    AttackStageInfo, ProcessNode
)

class AttackChainBuilder:
    def __init__(self):
        self.process_map: Dict[int, ProcessNode] = {}
        self.attack_chain = AttackChain()
        
    def build(self, timeline: Timeline, validated_iocs: List[Any]) -> AttackChain:
        self._build_process_tree(timeline)
        self._identify_malicious_processes(validated_iocs)
        self._map_to_attack_stages(timeline)
        self._identify_entry_point()
        self._generate_narrative()
        
        return self.attack_chain
    
    def _build_process_tree(self, timeline: Timeline):
        process_events = [e for e in timeline.events if e.event_type == EventType.PROCESS_CREATE]
        
        for event in process_events:
            pid = event.details.get("pid")
            ppid = event.details.get("ppid")
            
            if not pid:
                continue
            
            node = ProcessNode(
                pid=pid,
                ppid=ppid or 0,
                name=event.details.get("name", ""),
                cmdline=event.details.get("cmdline", ""),
                create_time=event.timestamp if event.timestamp.year > 2000 else None
            )
            
            self.process_map[pid] = node
        
        for pid, node in self.process_map.items():
            if node.ppid and node.ppid in self.process_map:
                parent = self.process_map[node.ppid]
                parent.children.append(node)
        
        roots = [n for n in self.process_map.values() if n.ppid == 0 or n.ppid not in self.process_map]
        self.attack_chain.process_tree = roots
    
    def _identify_malicious_processes(self, validated_iocs: List[Any]):
        malicious_pids = set()
        
        for ioc in validated_iocs:
            if ioc.verdict == "malicious":
                pid = ioc.ioc.context.get("pid")
                if pid:
                    malicious_pids.add(pid)
                    
                    if ioc.ioc.ioc_type == "injection":
                        if pid in self.process_map:
                            self.process_map[pid].injections.append({
                                "address": ioc.ioc.context.get("address"),
                                "protection": ioc.ioc.context.get("protection")
                            })
        
        for pid in malicious_pids:
            if pid in self.process_map:
                self.process_map[pid].is_malicious = True
                self._mark_ancestors_suspicious(pid)
    
    def _mark_ancestors_suspicious(self, pid: int):
        node = self.process_map.get(pid)
        if not node or not node.ppid:
            return
        
        parent = self.process_map.get(node.ppid)
        if parent:
            parent.is_suspicious = True
            self._mark_ancestors_suspicious(node.ppid)
    
    def _map_to_attack_stages(self, timeline: Timeline):
        self._identify_initial_access(timeline)
        self._identify_execution(timeline)
        self._identify_defense_evasion(timeline)
        self._identify_impact(timeline)
    
    def _identify_initial_access(self, timeline: Timeline):
        process_events = [e for e in timeline.events 
                         if e.event_type == EventType.PROCESS_CREATE 
                         and e.timestamp and e.timestamp.year > 2000]
        
        if not process_events:
            return
        
        suspicious_browsers = ["chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe"]
        office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        
        first_suspicious = None
        for event in process_events:
            name = event.details.get("name", "").lower()
            
            if any(browser in name for browser in suspicious_browsers):
                continue
            
            if any(office in name for office in office_apps):
                first_suspicious = event
                break
        
        if first_suspicious:
            stage = AttackStageInfo(
                stage=AttackStage.INITIAL_ACCESS,
                kill_chain_stage=KillChainStage.DELIVERY,
                timestamp=first_suspicious.timestamp,
                events=[first_suspicious.to_dict()],
                processes=[first_suspicious.details.get("pid")],
                description=f"Potential delivery via {first_suspicious.details.get('name')}",
                confidence=0.6
            )
            self.attack_chain.stages[AttackStage.INITIAL_ACCESS] = stage
    
    def _identify_execution(self, timeline: Timeline):
        malicious_procs = [pid for pid, node in self.process_map.items() if node.is_malicious]
        
        if not malicious_procs:
            return
        
        exec_events = [e for e in timeline.events 
                      if e.event_type == EventType.PROCESS_CREATE 
                      and e.details.get("pid") in malicious_procs]
        
        if exec_events:
            first_exec = min(exec_events, key=lambda x: x.timestamp if x.timestamp and x.timestamp.year > 2000 else datetime.max)
            
            stage = AttackStageInfo(
                stage=AttackStage.EXECUTION,
                kill_chain_stage=KillChainStage.EXPLOITATION,
                timestamp=first_exec.timestamp if first_exec.timestamp.year > 2000 else None,
                events=[e.to_dict() for e in exec_events[:5]],
                processes=malicious_procs[:5],
                description=f"Malicious code execution detected in {len(malicious_procs)} processes",
                confidence=0.9
            )
            self.attack_chain.stages[AttackStage.EXECUTION] = stage
    
    def _identify_defense_evasion(self, timeline: Timeline):
        injection_events = [e for e in timeline.events if e.event_type == EventType.CODE_INJECTION]
        
        if injection_events:
            stage = AttackStageInfo(
                stage=AttackStage.DEFENSE_EVASION,
                kill_chain_stage=KillChainStage.INSTALLATION,
                timestamp=injection_events[0].timestamp if injection_events[0].timestamp.year > 2000 else None,
                events=[e.to_dict() for e in injection_events],
                techniques=["T1055"],
                description=f"Process injection detected in {len(injection_events)} locations",
                confidence=0.95
            )
            self.attack_chain.stages[AttackStage.DEFENSE_EVASION] = stage
    
    def _identify_impact(self, timeline: Timeline):
        suspicious_files = [e for e in timeline.events 
                           if e.event_type == EventType.FILE_ACCESS 
                           and any(kw in e.description.lower() for kw in ["flag", "password", "ransom"])]
        
        if suspicious_files:
            stage = AttackStageInfo(
                stage=AttackStage.IMPACT,
                kill_chain_stage=KillChainStage.ACTIONS_ON_OBJECTIVES,
                timestamp=suspicious_files[0].timestamp if suspicious_files[0].timestamp.year > 2000 else None,
                events=[e.to_dict() for e in suspicious_files],
                description=f"Suspicious file operations: {', '.join(e.description for e in suspicious_files[:3])}",
                confidence=0.7
            )
            self.attack_chain.stages[AttackStage.IMPACT] = stage
    
    def _identify_entry_point(self):
        if AttackStage.INITIAL_ACCESS in self.attack_chain.stages:
            stage = self.attack_chain.stages[AttackStage.INITIAL_ACCESS]
            if stage.processes:
                self.attack_chain.entry_point_pid = stage.processes[0]
                
                node = self.process_map.get(stage.processes[0])
                if node:
                    self.attack_chain.initial_vector = node.name
    
    def _generate_narrative(self):
        narrative_parts = []
        
        sorted_stages = sorted(
            self.attack_chain.stages.items(),
            key=lambda x: x[1].timestamp if x[1].timestamp else datetime.max
        )
        
        if not sorted_stages:
            self.attack_chain.narrative = "No clear attack chain identified."
            return
        
        narrative_parts.append("ATTACK SEQUENCE:")
        narrative_parts.append("")
        
        for i, (stage_enum, stage_info) in enumerate(sorted_stages, 1):
            time_str = stage_info.timestamp.strftime("%H:%M:%S") if stage_info.timestamp else "Unknown time"
            narrative_parts.append(f"[Stage {i}] {stage_enum.value.upper().replace('_', ' ')} ({time_str})")
            narrative_parts.append(f"  {stage_info.description}")
            
            if stage_info.techniques:
                narrative_parts.append(f"  MITRE: {', '.join(stage_info.techniques)}")
            
            narrative_parts.append("")
        
        malicious_count = sum(1 for n in self.process_map.values() if n.is_malicious)
        suspicious_count = sum(1 for n in self.process_map.values() if n.is_suspicious and not n.is_malicious)
        
        narrative_parts.append(f"IMPACT: {malicious_count} malicious processes, {suspicious_count} suspicious processes identified.")
        
        self.attack_chain.narrative = "\n".join(narrative_parts)
        self.attack_chain.confidence = sum(s.confidence for s in self.attack_chain.stages.values()) / len(self.attack_chain.stages) if self.attack_chain.stages else 0.0
