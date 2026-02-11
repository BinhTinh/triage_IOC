from datetime import datetime
from typing import List, Dict, Any
from src.models.timeline import Timeline, EventType, EventSeverity
from src.models.attack_chain import AttackChain, ProcessNode


class TextVisualizer:
    
    @staticmethod
    def generate_timeline_chart(timeline: Timeline, max_events: int = 20) -> str:
        chart = []
        chart.append("="*80)
        chart.append("TIMELINE VISUALIZATION")
        chart.append("="*80)
        chart.append("")
        
        real_events = [e for e in timeline.events if e.timestamp and e.timestamp.year > 2000]
        real_events = sorted(real_events, key=lambda x: x.timestamp)[:max_events]
        
        if not real_events:
            chart.append("No timestamped events available for visualization")
            return "\n".join(chart)
        
        start_time = real_events[0].timestamp
        
        chart.append(f"Time Range: {timeline.start_time} to {timeline.end_time}")
        chart.append(f"Showing first {len(real_events)} events")
        chart.append("")
        
        severity_symbols = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "⚪"
        }
        
        for event in real_events:
            time_str = event.timestamp.strftime("%H:%M:%S")
            symbol = severity_symbols.get(event.severity.value, "○")
            
            elapsed = (event.timestamp - start_time).total_seconds()
            bar_length = min(int(elapsed / 60), 40)
            bar = "─" * bar_length + "●"
            
            event_desc = event.description[:50] + "..." if len(event.description) > 50 else event.description
            
            chart.append(f"{time_str} {symbol} {bar}")
            chart.append(f"         {event_desc}")
            chart.append("")
        
        chart.append("Legend:")
        chart.append("  🔴 Critical   🟠 High   🟡 Medium   🟢 Low   ⚪ Info")
        
        return "\n".join(chart)
    
    @staticmethod
    def generate_process_tree_diagram(attack_chain: AttackChain) -> str:
        diagram = []
        diagram.append("="*80)
        diagram.append("PROCESS TREE DIAGRAM")
        diagram.append("="*80)
        diagram.append("")
        
        if not attack_chain.process_tree:
            diagram.append("No process tree available")
            return "\n".join(diagram)
        
        diagram.append("Legend: 🔴 Malicious  ⚠️ Suspicious  ○ Normal")
        diagram.append("")
        
        def render_node(node: ProcessNode, indent: int = 0, is_last: bool = True, prefix: str = ""):
            lines = []
            
            connector = "└──" if is_last else "├──"
            
            if node.is_malicious:
                status = "🔴"
            elif node.is_suspicious:
                status = "⚠️ "
            else:
                status = "○ "
            
            name_display = f"{node.name} (PID: {node.pid})"
            
            if node.injections:
                name_display += f" [INJ:{len(node.injections)}]"
            
            lines.append(f"{prefix}{connector} {status} {name_display}")
            
            if node.children:
                extension = "    " if is_last else "│   "
                new_prefix = prefix + extension
                
                for i, child in enumerate(node.children):
                    child_is_last = (i == len(node.children) - 1)
                    lines.extend(render_node(child, indent + 1, child_is_last, new_prefix))
            
            return lines
        
        suspicious_roots = [n for n in attack_chain.process_tree if n.is_malicious or n.is_suspicious or any(c.is_malicious or c.is_suspicious for c in n.children)]
        
        roots_to_show = suspicious_roots if suspicious_roots else attack_chain.process_tree[:5]
        
        for root in roots_to_show:
            diagram.extend(render_node(root))
            diagram.append("")
        
        return "\n".join(diagram)
    
    @staticmethod
    def generate_attack_flow_diagram(attack_chain: AttackChain) -> str:
        flow = []
        flow.append("="*80)
        flow.append("ATTACK FLOW DIAGRAM")
        flow.append("="*80)
        flow.append("")
        
        if not attack_chain.stages:
            flow.append("No attack stages identified")
            return "\n".join(flow)
        
        sorted_stages = sorted(
            attack_chain.stages.items(),
            key=lambda x: x[1].timestamp if x[1].timestamp else datetime.max
        )
        
        max_width = 70
        
        for i, (stage_enum, stage_info) in enumerate(sorted_stages):
            stage_name = stage_enum.value.replace("_", " ").upper()
            
            box_content = f" {stage_name} "
            padding = max_width - len(box_content) - 2
            left_pad = padding // 2
            right_pad = padding - left_pad
            
            flow.append("┌" + "─" * max_width + "┐")
            flow.append("│" + " " * left_pad + box_content + " " * right_pad + "│")
            flow.append("└" + "─" * max_width + "┘")
            
            desc_lines = TextVisualizer._wrap_text(stage_info.description, max_width - 4)
            for line in desc_lines:
                flow.append(f"  {line}")
            
            if stage_info.techniques:
                flow.append(f"  MITRE: {', '.join(stage_info.techniques)}")
            
            flow.append(f"  Confidence: {stage_info.confidence:.0%}")
            
            if i < len(sorted_stages) - 1:
                flow.append("       │")
                flow.append("       ▼")
                flow.append("")
        
        return "\n".join(flow)
    
    @staticmethod
    def _wrap_text(text: str, width: int) -> List[str]:
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + 1 <= width:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(" ".join(current_line))
        
        return lines
    
    @staticmethod
    def generate_statistics_chart(timeline: Timeline, validated_iocs: List) -> str:
        chart = []
        chart.append("="*80)
        chart.append("STATISTICS OVERVIEW")
        chart.append("="*80)
        chart.append("")
        
        malicious = len([ioc for ioc in validated_iocs if ioc.verdict == "malicious"])
        suspicious = len([ioc for ioc in validated_iocs if ioc.verdict == "suspicious"])
        benign = len([ioc for ioc in validated_iocs if ioc.verdict == "benign"])
        
        chart.append("IOC Distribution:")
        chart.append("")
        
        total = malicious + suspicious + benign
        if total > 0:
            mal_pct = (malicious / total) * 100
            sus_pct = (suspicious / total) * 100
            ben_pct = (benign / total) * 100
            
            mal_bar = "█" * int(mal_pct / 2)
            sus_bar = "█" * int(sus_pct / 2)
            ben_bar = "█" * int(ben_pct / 2)
            
            chart.append(f"  Malicious  [{mal_bar:<50}] {malicious} ({mal_pct:.1f}%)")
            chart.append(f"  Suspicious [{sus_bar:<50}] {suspicious} ({sus_pct:.1f}%)")
            chart.append(f"  Benign     [{ben_bar:<50}] {benign} ({ben_pct:.1f}%)")
        
        chart.append("")
        chart.append("Event Types:")
        chart.append("")
        
        for event_type, count in sorted(timeline.event_types.items(), key=lambda x: x[1], reverse=True):
            bar_length = min(int(count / 2), 50)
            bar = "█" * bar_length
            chart.append(f"  {event_type:<20} [{bar:<50}] {count}")
        
        return "\n".join(chart)
