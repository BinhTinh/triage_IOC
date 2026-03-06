import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

from src.core.decision_engine import DecisionEngine, get_triage_plan
from src.core.volatility_executor import VolatilityExecutor
from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.core.mitre_mapper import MITREMapper
from src.core.report_generator import ReportGenerator
from src.core.symbol_resolver import SymbolResolver
from src.core.timeline_builder import TimelineBuilder
from src.models.case import Case, CaseStatus
from src.models.ioc import IOC, ValidatedIOC
from src.models.timeline import EventSeverity
from src.config.settings import settings
from src.utils.logging import get_logger
from src.core.attack_chain_builder import AttackChainBuilder
from src.core.behavior_analyzer import BehaviorAnalyzer
from src.core.narrative_generator import NarrativeGenerator
from src.core.visualization import TextVisualizer

logger = get_logger(__name__)

class AnalysisPipeline:
    def __init__(
        self,
        progress_callback: Optional[Callable] = None,
        log_callback: Optional[Callable] = None
    ):
        self.executor = VolatilityExecutor()
        self.decision_engine = DecisionEngine()
        self.symbol_resolver = SymbolResolver()
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        
        self._plugin_results: Dict[str, dict] = {}
        self._raw_iocs: List[dict] = []
        self._validated_iocs: List[ValidatedIOC] = []
    
    async def _log(self, message: str, level: str = "info"):
        if self.log_callback:
            await self.log_callback(message, level)
        logger.info(message)
    
    async def _progress(self, current: int, total: int, message: str):
        if self.progress_callback:
            await self.progress_callback(current, total, message)
    
    async def detect_os(self, dump_path: str) -> dict:
        await self._log(f"Detecting OS for {dump_path}")
        
        try:
            result = await self.executor.run_plugin(dump_path, "windows.info")
            if result.success and result.data:
                return {
                    "os_type": "windows",
                    "version": str(result.data[0].get("NtMajorVersion", "unknown")),
                    "build": str(result.data[0].get("NtBuildNumber", "unknown")),
                    "arch": "x64" if result.data[0].get("Is64Bit", True) else "x86"
                }
        except Exception:
            pass
        
        try:
            result = await self.executor.run_plugin(dump_path, "banners.Banners")
            if result.success and result.data:
                import re
                for banner in result.data:
                    banner_text = banner.get("Banner", "")
                    match = re.search(r"Linux version (\d+\.\d+\.\d+)", banner_text)
                    if match:
                        return {
                            "os_type": "linux",
                            "version": match.group(1),
                            "arch": "x64"
                        }
        except Exception:
            pass
        
        await self._log("Could not detect OS, defaulting to Windows", "warning")
        return {"os_type": "windows", "version": "unknown", "arch": "x64"}
    
    async def run_analysis(
        self,
        dump_path: str,
        goal: str = "malware_detection",
        output_dir: Optional[str] = None
    ) -> dict:
        await self._log(f"Starting analysis pipeline for {dump_path}")
        await self._log(f"Analysis goal: {goal}")
        
        report_gen = ReportGenerator(output_dir)
        
        os_info = await self.detect_os(dump_path)
        await self._log(f"Detected OS: {os_info['os_type']} {os_info.get('version', 'unknown')}")
        
        case = Case(
            dump_path=dump_path,
            dump_hash=await self.executor.get_dump_hash(dump_path),
            os_type=os_info["os_type"],
            os_version=os_info.get("version", "unknown"),
            os_arch=os_info.get("arch", "x64"),
            goal=goal
        )
        case.status = CaseStatus.RUNNING
        
        case_dir = report_gen.create_case_directory(case)
        await self._log(f"Created case directory: {case_dir}")
        
        if os_info["os_type"] == "linux":
            await self._log("Checking Linux symbols...")
            symbol_status = await self.symbol_resolver.check_symbols(dump_path)
            if not symbol_status["available"]:
                await self._log(f"Warning: Linux symbols not available - {symbol_status['message']}", "warning")
        
        plan = get_triage_plan(os_info["os_type"], goal)
        plugins = [p["name"] for p in plan.plugins]
        await self._log(f"Triage plan: {len(plugins)} plugins, estimated {plan.estimated_minutes} minutes")
        
        await self._log("Phase 2: Executing plugins...")
        total_plugins = len(plugins)
        
        for i, plugin in enumerate(plugins, 1):
            await self._progress(i, total_plugins, f"Running {plugin}")
            await self._log(f"[{i}/{total_plugins}] Running {plugin}...")
            
            start_time = datetime.now()
            if isinstance(plugin, dict):
                plugin_name = plugin["name"]
                plugin_args = plugin.get("args", [])
                result = await self.executor.run_plugin(dump_path, plugin_name, plugin_args)
            else:
                result = await self.executor.run_plugin(dump_path, plugin)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            self._plugin_results[plugin] = {
                "success": result.success,
                "rows": len(result.data or []),
                "error": result.error,
                "execution_time": execution_time,
                "data": result.data
            }
            
            report_gen.save_plugin_output(
                plugin_name=plugin,
                data=result.data,
                success=result.success,
                error=result.error,
                execution_time=execution_time
            )
            
            status = "✓" if result.success else "✗"
            rows = len(result.data or [])
            await self._log(f"  [{status}] {plugin}: {rows} rows ({execution_time:.1f}s)")
        
        await self._log("Phase 3: Building Timeline...")
        timeline_builder = TimelineBuilder(os_info["os_type"])
        timeline = timeline_builder.build(self._plugin_results)
        
        case.timeline = timeline
        
        await self._log(f"Timeline: {timeline.total_events} events ({timeline.start_time} to {timeline.end_time})")
        
        timeline_path = report_gen.save_timeline(timeline)
        await self._log(f"Saved: {timeline_path}")
        
        await self._log("Phase 4: Extracting IOCs...")
        extractor = ExtractionPipeline(os_info["os_type"])
        
        plugin_data = {k: v["data"] for k, v in self._plugin_results.items() if v.get("data")}
        extracted_iocs = await extractor.extract(plugin_data)
        
        self._raw_iocs = [ioc.to_dict() for ioc in extracted_iocs]
        await self._log(f"Extracted {len(extracted_iocs)} potential IOCs")
        
        await self._log("Phase 5: Validating IOCs...")
        if settings.use_deepseek:
            from src.core.deepseek_validator import HybridValidator
            
            config = {
                "deepseek_api_key": settings.deepseek_api_key,
                "use_local_patterns": settings.use_local_patterns
            }
            
            validator = HybridValidator(config)
            self._validated_iocs = await validator.validate_batch(extracted_iocs, os_info["os_type"])
        else:
            from src.core.validator import ValidationPipeline
            
            config = {
                "vt_api_key": settings.vt_api_key,
                "abuse_api_key": settings.abuseipdb_key
            }
            
            validator = ValidationPipeline(config)
            self._validated_iocs = await validator.validate_batch(extracted_iocs, os_info["os_type"])
        
        malicious = [i for i in self._validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in self._validated_iocs if i.verdict == "suspicious"]
        benign = [i for i in self._validated_iocs if i.verdict == "benign"]
        
        await self._log(f"Validation complete: {len(malicious)} malicious, {len(suspicious)} suspicious, {len(benign)} benign")
        
        await self._log("Phase 6: Mapping to MITRE ATT&CK...")
        mapper = MITREMapper()
        mitre_report = mapper.map_iocs(self._validated_iocs)
        
        mitre_mapping = {
            "total_techniques": mitre_report.total_techniques,
            "tactics_involved": list(mitre_report.tactics.keys()),
            "matrix": mapper.generate_matrix(mitre_report),
            "techniques": [
                {
                    "id": tid,
                    "name": data["technique"]["name"],
                    "tactic": data["technique"]["tactic"],
                    "description": data["technique"].get("description", ""),
                    "ioc_count": len(data["iocs"]),
                    "recommendations": data["technique"].get("recommendations", [])
                }
                for tid, data in mitre_report.techniques.items()
            ]
        }
        
        await self._log(f"Mapped to {mitre_report.total_techniques} MITRE ATT&CK techniques")
        
        await self._log("Phase 7: Building Attack Chain...")
        chain_builder = AttackChainBuilder()
        attack_chain = chain_builder.build(timeline, self._validated_iocs)
        
        case.attack_chain = attack_chain
        
        await self._log(f"Attack chain: {len(attack_chain.stages)} stages identified")
        if attack_chain.initial_vector:
            await self._log(f"Entry point: {attack_chain.initial_vector} (PID {attack_chain.entry_point_pid})")
        
        attack_chain_path = report_gen.save_attack_chain(attack_chain)
        await self._log(f"Saved: {attack_chain_path}")
        
        await self._log("Phase 8: Analyzing Behavior Patterns...")
        behavior_analyzer = BehaviorAnalyzer()
        malware_classification = behavior_analyzer.analyze(timeline, attack_chain, self._validated_iocs)
        
        case.malware_classification = malware_classification
        
        await self._log(f"Malware family: {malware_classification.get('family', 'Unknown')} ({malware_classification.get('confidence', 0):.0%} confidence)")
        await self._log(f"Matched patterns: {len(malware_classification.matched_patterns)}")
        
        behavior_path = report_gen.save_behavior_analysis(malware_classification)
        await self._log(f"Saved: {behavior_path}")
        
        await self._log("Phase 9: Generating Enhanced Reports...")
        
        await self._log("Generating visualizations...")
        viz_path = report_gen.save_visualizations(timeline, attack_chain, self._validated_iocs)
        await self._log(f"Saved: {viz_path}")
        
        await self._log("Generating narrative report...")
        narrative_path = report_gen.save_narrative(
            timeline, attack_chain, malware_classification, self._validated_iocs
        )
        await self._log(f"Saved: {narrative_path}")
        
        iocs_json_path = report_gen.save_iocs_json(self._validated_iocs, self._raw_iocs)
        await self._log(f"Saved IOCs JSON: {iocs_json_path}")
        
        plugin_summary = {k: {"success": v["success"], "rows": v["rows"]} for k, v in self._plugin_results.items()}
        summary_path = report_gen.save_summary(case, self._validated_iocs, mitre_mapping, plugin_summary)
        await self._log(f"Saved Summary: {summary_path}")
        
        case.status = CaseStatus.COMPLETED
        case.findings_count = len(self._validated_iocs)
        case.iocs_count = len(malicious) + len(suspicious)
        
        report = report_gen.generate(case, self._validated_iocs, mitre_mapping)
        
        await self._log("="*60)
        await self._log("ANALYSIS COMPLETE")
        await self._log("="*60)
        await self._log(f"Case ID: {case.id}")
        await self._log(f"Threat Level: {report.summary['threat_level']}")
        await self._log(f"Threat Score: {report.summary['threat_score']}/100")
        await self._log(f"Malicious IOCs: {len(malicious)}")
        await self._log(f"Timeline Events: {timeline.total_events}")
        await self._log(f"Report Directory: {case_dir}")
        
        if settings.use_deepseek:
            try:
                if hasattr(validator, 'close'):
                    await validator.close()
                    await self._log("Closed validator session")
            except Exception as e:
                await self._log(f"Warning: Could not close validator: {e}", "warning")
        
        return {
            "case_id": case.id,
            "status": "completed",
            "threat_level": report.summary["threat_level"],
            "threat_score": report.summary["threat_score"],
            "summary": report.summary,
            "report_directory": str(case_dir),
            "files": {
                "summary": summary_path,
                "iocs_json": iocs_json_path,
                "timeline_json": timeline_path,
                "plugins_dir": str(case_dir / "plugins")
            },
            "top_recommendations": report.recommendations[:5],
            "timeline_events": timeline.total_events
        }

async def run_ioc_extraction(
    dump_path: str,
    goal: str = "malware_detection",
    output_dir: Optional[str] = None
) -> dict:
    pipeline = AnalysisPipeline()
    return await pipeline.run_analysis(dump_path, goal, output_dir)
