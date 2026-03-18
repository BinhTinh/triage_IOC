import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import yaml
import json


from src.models.ioc import IOC, ValidatedIOC, ValidationResult
from src.config.settings import settings


try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False



class WhitelistValidator:
    def __init__(self, whitelist_path: Optional[str] = None):
        self.whitelist = self._load_whitelist(whitelist_path)
        self.ip_networks = []
        self.domain_patterns = []
        self._compile_patterns()
    
    def _load_whitelist(self, path: Optional[str]) -> dict:
        if path and Path(path).exists():
            with open(path) as f:
                return yaml.safe_load(f)
        
        config_path = Path(settings.config_dir) / "whitelist.yaml"
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        
        return self._get_default_whitelist()
    
    def _get_default_whitelist(self) -> dict:
        return {
            "ips": [
                {"value": "8.8.8.8", "reason": "Google DNS"},
                {"value": "8.8.4.4", "reason": "Google DNS"},
                {"value": "1.1.1.1", "reason": "Cloudflare DNS"},
            ],
            "ip_ranges": [
                {"range": "10.0.0.0/8", "reason": "Private network"},
                {"range": "172.16.0.0/12", "reason": "Private network"},
                {"range": "192.168.0.0/16", "reason": "Private network"},
                {"range": "127.0.0.0/8", "reason": "Loopback"},
            ],
            "domains": [
                {"pattern": "*.microsoft.com", "reason": "Microsoft"},
                {"pattern": "*.google.com", "reason": "Google"},
                {"pattern": "*.windows.com", "reason": "Microsoft"},
            ],
            "processes": {
                "windows": [
                    {"path": "C:\\Windows\\System32\\svchost.exe", "reason": "Windows Service Host"},
                    {"path": "C:\\Windows\\System32\\csrss.exe", "reason": "Client/Server Runtime"},
                    {"path": "C:\\Windows\\System32\\smss.exe", "reason": "Session Manager"},
                    {"path": "C:\\Windows\\System32\\winlogon.exe", "reason": "Windows Logon"},
                    {"path": "C:\\Windows\\System32\\services.exe", "reason": "Service Control Manager"},
                    {"path": "C:\\Windows\\System32\\lsass.exe", "reason": "Local Security Authority"},
                    {"path": "C:\\Windows\\System32\\wininit.exe", "reason": "Windows Init"},
                    {"path": "C:\\Windows\\System32\\explorer.exe", "reason": "Windows Explorer"},
                    {"path": "C:\\Windows\\System32\\dwm.exe", "reason": "Desktop Window Manager"},
                    {"path": "C:\\Windows\\System32\\spoolsv.exe", "reason": "Print Spooler"},
                    {"path": "C:\\Windows\\System32\\MsMpEng.exe", "reason": "Windows Defender"},
                    {"path": "C:\\Windows\\System32\\NisSrv.exe", "reason": "Windows Defender Network"},
                    {"path": "C:\\Windows\\System32\\ctfmon.exe", "reason": "CTF Loader"},
                    {"path": "C:\\Windows\\System32\\taskhostw.exe", "reason": "Task Host"},
                    {"path": "C:\\Windows\\System32\\sihost.exe", "reason": "Shell Infrastructure Host"},
                    {"path": "C:\\Windows\\System32\\SearchHost.exe", "reason": "Windows Search"},
                    {"path": "C:\\Windows\\System32\\WUDFHost.exe", "reason": "WUDF Host"},
                    {"path": "C:\\Windows\\System32\\dllhost.exe", "reason": "COM Surrogate"},
                    {"path": "C:\\Windows\\System32\\msdtc.exe", "reason": "DTC Service"},
                    {"path": "C:\\Windows\\System32\\WmiPrvSE.exe", "reason": "WMI Provider"},
                    {"path": "C:\\Windows\\System32\\fontdrvhost.exe", "reason": "Font Driver Host"},
                    {"path": "svchost.exe", "reason": "Service Host (short name)"},
                    {"path": "csrss.exe", "reason": "CSRSS (short name)"},
                    {"path": "smss.exe", "reason": "SMSS (short name)"},
                    {"path": "winlogon.exe", "reason": "Winlogon (short name)"},
                    {"path": "services.exe", "reason": "Services (short name)"},
                    {"path": "lsass.exe", "reason": "LSASS (short name)"},
                    {"path": "wininit.exe", "reason": "Wininit (short name)"},
                    {"path": "explorer.exe", "reason": "Explorer (short name)"},
                    {"path": "dwm.exe", "reason": "DWM (short name)"},
                    {"path": "spoolsv.exe", "reason": "Spooler (short name)"},
                    {"path": "MsMpEng.exe", "reason": "Defender (short name)"},
                    {"path": "NisSrv.exe", "reason": "Defender Network (short name)"},
                    {"path": "vmtoolsd.exe", "reason": "VMware Tools"},
                    {"path": "vm3dservice.exe", "reason": "VMware 3D Service"},
                ],
                "linux": [
                    {"path": "/sbin/init", "reason": "Init process"},
                    {"path": "/usr/lib/systemd/systemd", "reason": "Systemd"},
                ]
            },
            "hashes": [
                {"value": "d41d8cd98f00b204e9800998ecf8427e", "reason": "Empty file MD5"},
            ]
        }
    
    def _compile_patterns(self):
        for r in self.whitelist.get("ip_ranges", []):
            try:
                self.ip_networks.append(ipaddress.ip_network(r["range"]))
            except ValueError:
                pass
        
        for d in self.whitelist.get("domains", []):
            pattern = d["pattern"].replace(".", r"\.").replace("*", ".*")
            self.domain_patterns.append(re.compile(pattern, re.IGNORECASE))
    
    def check_ip(self, ip: str) -> Tuple[bool, str]:
        known_ips = [w["value"] for w in self.whitelist.get("ips", [])]
        if ip in known_ips:
            return True, "Known safe IP"
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.ip_networks:
                if ip_obj in network:
                    return True, f"Private/Reserved range: {network}"
        except ValueError:
            pass
        
        return False, ""
    
    def check_domain(self, domain: str) -> Tuple[bool, str]:
        for pattern in self.domain_patterns:
            if pattern.search(domain):
                return True, "Known safe domain"
        return False, ""

    
    def check_hash(self, hash_value: str) -> Tuple[bool, str]:
        known_hashes = [h["value"].lower() for h in self.whitelist.get("hashes", [])]
        if hash_value.lower() in known_hashes:
            return True, "Known safe hash"
        return False, ""
    
    def check_process(self, path: str, os_type: str) -> Tuple[bool, str]:
        processes = self.whitelist.get("processes", {}).get(os_type, [])
        known_paths = [p["path"].lower() for p in processes]
        if path.lower() in known_paths:
            return True, "Known system process"
        return False, ""
    
    def validate(self, ioc: IOC, os_type: str = "windows") -> ValidationResult:
        is_whitelisted = False
        reason = ""
        ioc_type = str(ioc.ioc_type).lower()
        
        if ioc_type in {"ip", "ipv4", "ipv6"}:
            is_whitelisted, reason = self.check_ip(ioc.value)
        elif ioc_type == "domain":
            is_whitelisted, reason = self.check_domain(ioc.value)
        elif ioc_type in ["md5", "sha1", "sha256", "hash"]:
            is_whitelisted, reason = self.check_hash(ioc.value)
        elif ioc_type == "process":
            is_whitelisted, reason = self.check_process(ioc.value, os_type)
        
        return ValidationResult(
            source="whitelist",
            is_malicious=False,
            is_whitelisted=is_whitelisted,
            score=0.0 if is_whitelisted else 0.5,
            reason=reason
        )

class VirusTotalValidator:
    BASE_URL = "https://www.virustotal.com/api/v3"
    CACHE_TTL = 21600

    def __init__(self, api_key: str, redis_client=None):
        self.api_key = api_key
        self.session = None
        self._lock = asyncio.Lock()
        self._mem_cache: Dict[str, Optional[dict]] = {}
        self._redis = redis_client
        self.last_request = 0.0

    async def _get_session(self):
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available")
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _request(self, endpoint: str) -> Optional[dict]:
        if endpoint in self._mem_cache:
            return self._mem_cache[endpoint]

        if self._redis:
            try:
                cached = await self._redis.get(f"vt:{endpoint}")
                if cached:
                    result = json.loads(cached)
                    self._mem_cache[endpoint] = result
                    return result
            except Exception:
                pass

        async with self._lock:
            if endpoint in self._mem_cache:
                return self._mem_cache[endpoint]

            now = time.time()
            wait = max(0.0, 15.0 - (now - self.last_request))
            if wait:
                await asyncio.sleep(wait)

            session = await self._get_session()
            try:
                async with session.get(
                    f"{self.BASE_URL}/{endpoint}",
                    headers={"x-apikey": self.api_key},
                ) as resp:
                    self.last_request = time.time()
                    result = await resp.json() if resp.status == 200 else None
                    self._mem_cache[endpoint] = result
                    if self._redis and result:
                        try:
                            await self._redis.setex(
                                f"vt:{endpoint}",
                                self.CACHE_TTL,
                                json.dumps(result)
                            )
                        except Exception:
                            pass
                    return result
            except Exception:
                return None

    def _parse_stats(self, data: Optional[dict], threshold: float = 0.3) -> ValidationResult:
        if not data:
            return ValidationResult(source="virustotal", is_malicious=False, score=0.0, reason="Not found in VT")
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = (malicious + suspicious * 0.5) / total
        return ValidationResult(
            source="virustotal",
            is_malicious=score > threshold,
            score=score,
            reason=f"VT: {malicious}/{total} malicious",
            raw_data=stats,
        )

    async def check_ip(self, ip: str) -> ValidationResult:
        return self._parse_stats(await self._request(f"ip_addresses/{ip}"))

    async def check_domain(self, domain: str) -> ValidationResult:
        return self._parse_stats(await self._request(f"domains/{domain}"))

    async def check_hash(self, hash_value: str) -> ValidationResult:
        return self._parse_stats(await self._request(f"files/{hash_value}"), threshold=0.1)

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None


class AbuseIPDBValidator:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    CACHE_TTL = 21600
    
    def __init__(self, api_key: str, redis_client=None):
        self.api_key = api_key
        self.session = None
        self._redis = redis_client
    
    async def _get_session(self):
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available")
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def check_ip(self, ip: str) -> ValidationResult:
        if self._redis:
            try:
                cached = await self._redis.get(f"abuse:{ip}")
                if cached:
                    data = json.loads(cached)
                    return ValidationResult(**data)
            except Exception:
                pass

        session = await self._get_session()
        try:
            async with session.get(
                f"{self.BASE_URL}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            ) as resp:
                if resp.status != 200:
                    return ValidationResult(
                        source="abuseipdb", is_malicious=False,
                        score=0.5, reason="AbuseIPDB API error"
                    )
                data = await resp.json()
                abuse_data = data.get("data", {})
                confidence = abuse_data.get("abuseConfidencePercentage", 0) / 100
                total_reports = abuse_data.get("totalReports", 0)
                result = ValidationResult(
                    source="abuseipdb",
                    is_malicious=confidence > 0.5,
                    score=confidence,
                    reason=f"AbuseIPDB: {confidence*100:.0f}% confidence, {total_reports} reports",
                    raw_data={
                        "confidence": confidence,
                        "total_reports": total_reports,
                        "country": abuse_data.get("countryCode"),
                        "isp": abuse_data.get("isp"),
                    },
                )
                if self._redis:
                    try:
                        await self._redis.setex(
                            f"abuse:{ip}",
                            self.CACHE_TTL,
                            json.dumps(result.__dict__)
                        )
                    except Exception:
                        pass
                return result
        except Exception as e:
            return ValidationResult(
                source="abuseipdb", is_malicious=False,
                score=0.5, reason=f"AbuseIPDB error: {e}"
            )
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None



class ValidationPipeline:
    VT_CONFIDENCE_THRESHOLD = 0.35
    VT_ELIGIBLE_TYPES = {"ip", "ipv4", "domain", "md5", "sha1", "sha256", "hash"}
    CONTEXT_ONLY_TYPES = {
        "injection", "process", "command", "pipe",
        "registry_persistence", "registry_defense_evasion",
        "registry_credential_access",
    }
    EVIDENCE_TYPES = {"ipv4", "ip", "domain", "md5", "sha1", "sha256", "hash", "filepath"}


    def __init__(self, config: dict, redis_client=None):
        self.whitelist = WhitelistValidator()
        self.enable_threat_intel = bool(config.get("enable_threat_intel", False))
        self.vt = (
            VirusTotalValidator(config["vt_api_key"], redis_client=redis_client)
            if self.enable_threat_intel and config.get("vt_api_key")
            else None
        )
        self.abuse = (
            AbuseIPDBValidator(config["abuse_api_key"], redis_client=redis_client)
            if self.enable_threat_intel and config.get("abuse_api_key")
            else None
        )
        self.weights = {"virustotal": 0.4, "abuseipdb": 0.3, "whitelist": 0.3}

    def _calculate_final_score(self, results: List[ValidationResult], base_confidence: float) -> float:
        if not results:
            return base_confidence
        weighted_sum = sum(r.score * self.weights.get(r.source, 0.2) for r in results)
        weight_sum = sum(self.weights.get(r.source, 0.2) for r in results)
        return weighted_sum / weight_sum if weight_sum else base_confidence

    def _determine_verdict(self, score: float) -> str:
        if score >= 0.7:
            return "malicious"
        elif score >= 0.4:
            return "suspicious"
        return "benign"

    def _generate_reason(self, results: List[ValidationResult]) -> str:
        reasons = [r.reason for r in results if r.reason]
        return " | ".join(reasons) if reasons else "No validation data"

    @staticmethod
    def _ioc_type_str(ioc: IOC) -> str:
        return str(ioc.ioc_type).lower()

    def _score_context_only_ioc(self, ioc: IOC) -> float:
        ioc_type = self._ioc_type_str(ioc)
        ctx = ioc.context or {}
        src = str(ioc.source_plugin or "").lower()

        # Start conservative for behavior-only artifacts to reduce one-off false positives.
        score = max(0.20, min(0.85, float(ioc.confidence) * 0.75))

        if ctx.get("technique"):
            score += 0.05

        if ioc_type == "injection":
            if bool(ctx.get("has_pe_header")):
                score += 0.15
            protection = str(ctx.get("protection", "")).lower()
            if "execute_readwrite" in protection or "rwx" in protection:
                score += 0.10
            if "malfind" in src or "hollowprocesses" in src:
                score += 0.05

        if ioc_type == "command":
            cmd = str(ioc.value or "").lower()
            high_risk_markers = (
                "-enc", "frombase64string", "invoke-expression", " iwr ", "iex",
                "mshta", "certutil", "bitsadmin", "rundll32", "regsvr32",
            )
            if any(m in cmd for m in high_risk_markers):
                score += 0.10

        return min(0.95, score)

    def _apply_correlation_guard(self, items: List[ValidatedIOC]) -> List[ValidatedIOC]:
        if not items:
            return items

        evidence_malicious = 0
        technique_counts: Dict[str, int] = {}

        for item in items:
            ioc_type = str(item.ioc.ioc_type).lower()
            if item.verdict == "malicious" and ioc_type in self.EVIDENCE_TYPES:
                evidence_malicious += 1

            technique = str((item.ioc.context or {}).get("technique", "")).strip()
            if technique:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1

        for item in items:
            ioc_type = str(item.ioc.ioc_type).lower()
            if item.verdict != "malicious" or ioc_type not in self.CONTEXT_ONLY_TYPES:
                continue

            technique = str((item.ioc.context or {}).get("technique", "")).strip()
            repeated_technique = bool(technique and technique_counts.get(technique, 0) >= 2)
            has_external_support = any(r.source in {"virustotal", "abuseipdb"} for r in item.validation_results)

            # Guardrail: isolated behavior-only malicious alerts are downgraded to suspicious.
            if not (evidence_malicious > 0 or repeated_technique or has_external_support):
                item.verdict = "suspicious"
                item.final_confidence = min(item.final_confidence, 0.69)
                guard_reason = "Correlation guard: isolated behavior-only finding"
                if item.reason:
                    item.reason = f"{item.reason} | {guard_reason}"
                else:
                    item.reason = guard_reason

        return items

    async def validate_ioc(self, ioc: IOC, os_type: str = "windows") -> ValidatedIOC:
        results: List[ValidationResult] = []

        whitelist_result = self.whitelist.validate(ioc, os_type)
        if whitelist_result.is_whitelisted:
            return ValidatedIOC(ioc=ioc, final_confidence=0.05,
                                verdict="benign", validation_results=[whitelist_result],
                                reason=whitelist_result.reason)

        if self._ioc_type_str(ioc) in self.CONTEXT_ONLY_TYPES:
            score = self._score_context_only_ioc(ioc)
            return ValidatedIOC(
                ioc=ioc,
                final_confidence=score,
                verdict=self._determine_verdict(score),
                validation_results=results,
                reason=f"Context-confirmed, extraction confidence={score:.2f}",
            )
        skip_vt = False

        vt_result = None
        if self.vt and not skip_vt and ioc.ioc_type in self.VT_ELIGIBLE_TYPES:
            try:
                if ioc.ioc_type in ("ip", "ipv4"):
                    vt_result = await self.vt.check_ip(ioc.value)
                elif ioc.ioc_type == "domain":
                    vt_result = await self.vt.check_domain(ioc.value)
                else:
                    vt_result = await self.vt.check_hash(ioc.value)
                if vt_result:
                    results.append(vt_result)
            except Exception:
                pass

        if self.abuse and ioc.ioc_type in ("ip", "ipv4"):
            try:
                results.append(await self.abuse.check_ip(ioc.value))
            except Exception:
                pass
        if not results:
            final_score = ioc.confidence
        else:
            weighted_sum = sum(r.score * self.weights.get(r.source, 0.2) for r in results)
            weight_sum   = sum(self.weights.get(r.source, 0.2) for r in results)

            if vt_result and vt_result.score >= 0.40:
                vt_weight = 0.50
                ab_weight = 0.15 if (self.abuse and ioc.ioc_type in ("ip", "ipv4")) else 0.0
                total_w   = vt_weight + ab_weight

                final_score = (
                    vt_result.score * vt_weight
                    + (results[-1].score * ab_weight if ab_weight else 0)
                ) / (total_w or 1)
            else:
                final_score = weighted_sum / weight_sum if weight_sum else ioc.confidence

        return ValidatedIOC(
            ioc=ioc,
            final_confidence=min(final_score, 0.99),
            verdict=self._determine_verdict(final_score),
            validation_results=results,
            reason=self._generate_reason(results),
        )

    async def validate_batch(
        self, iocs: List[IOC], os_type: str = "windows", max_concurrent: int = 5
    ) -> List[ValidatedIOC]:
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _run(ioc: IOC) -> ValidatedIOC:
            async with semaphore:
                return await self.validate_ioc(ioc, os_type)

        items = list(await asyncio.gather(*[_run(i) for i in iocs]))
        return self._apply_correlation_guard(items)

    
    async def close(self):
        if self.vt:
            await self.vt.close()
        if self.abuse:
            await self.abuse.close()


    _shared_redis = None

    @staticmethod
    def set_redis_client(client) -> None:
        global _shared_redis
        _shared_redis = client

    @staticmethod
    def get_redis_client():
        return _shared_redis
