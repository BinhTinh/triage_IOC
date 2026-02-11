import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import yaml

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
            if pattern.match(domain):
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
        
        if ioc.ioc_type == "ip":
            is_whitelisted, reason = self.check_ip(ioc.value)
        elif ioc.ioc_type == "domain":
            is_whitelisted, reason = self.check_domain(ioc.value)
        elif ioc.ioc_type in ["md5", "sha1", "sha256", "hash"]:
            is_whitelisted, reason = self.check_hash(ioc.value)
        elif ioc.ioc_type == "process":
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
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
        self.rate_limiter = asyncio.Semaphore(4)
        self.last_request = 0
    
    async def _get_session(self):
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available")
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def _request(self, endpoint: str) -> Optional[dict]:
        async with self.rate_limiter:
            now = time.time()
            wait_time = max(0, 15 - (now - self.last_request))
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            
            session = await self._get_session()
            headers = {"x-apikey": self.api_key}
            url = f"{self.BASE_URL}/{endpoint}"
            
            try:
                async with session.get(url, headers=headers) as resp:
                    self.last_request = time.time()
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        return None
                    else:
                        return None
            except Exception:
                return None
    
    async def check_ip(self, ip: str) -> ValidationResult:
        data = await self._request(f"ip_addresses/{ip}")
        
        if not data:
            return ValidationResult(
                source="virustotal",
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        
        score = (malicious * 1.0 + suspicious * 0.5) / total
        
        return ValidationResult(
                        source="virustotal",
            is_malicious=score > 0.3,
            score=score,
            reason=f"VT: {malicious}/{total} malicious, {suspicious}/{total} suspicious",
            raw_data=stats
        )
    
    async def check_domain(self, domain: str) -> ValidationResult:
        data = await self._request(f"domains/{domain}")
        
        if not data:
            return ValidationResult(
                source="virustotal",
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        
        score = (malicious * 1.0 + suspicious * 0.5) / total
        
        return ValidationResult(
            source="virustotal",
            is_malicious=score > 0.3,
            score=score,
            reason=f"VT: {malicious}/{total} malicious",
            raw_data=stats
        )
    
    async def check_hash(self, hash_value: str) -> ValidationResult:
        data = await self._request(f"files/{hash_value}")
        
        if not data:
            return ValidationResult(
                source="virustotal",
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        
        score = malicious / total
        
        return ValidationResult(
            source="virustotal",
            is_malicious=score > 0.3,
            score=score,
            reason=f"VT: {malicious}/{total} detections",
            raw_data=stats
        )
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


class AbuseIPDBValidator:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
    
    async def _get_session(self):
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available")
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def check_ip(self, ip: str) -> ValidationResult:
        session = await self._get_session()
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        
        try:
            async with session.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params
            ) as resp:
                if resp.status != 200:
                    return ValidationResult(
                        source="abuseipdb",
                        is_malicious=False,
                        score=0.5,
                        reason="AbuseIPDB API error"
                    )
                
                data = await resp.json()
                abuse_data = data.get("data", {})
                
                confidence = abuse_data.get("abuseConfidencePercentage", 0) / 100
                total_reports = abuse_data.get("totalReports", 0)
                
                return ValidationResult(
                    source="abuseipdb",
                    is_malicious=confidence > 0.5,
                    score=confidence,
                    reason=f"AbuseIPDB: {confidence*100:.0f}% confidence, {total_reports} reports",
                    raw_data={
                        "confidence": confidence,
                        "total_reports": total_reports,
                        "country": abuse_data.get("countryCode"),
                        "isp": abuse_data.get("isp")
                    }
                )
        except Exception as e:
            return ValidationResult(
                source="abuseipdb",
                is_malicious=False,
                score=0.5,
                reason=f"AbuseIPDB error: {str(e)}"
            )
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


class ValidationPipeline:
    def __init__(self, config: dict):
        self.whitelist = WhitelistValidator()
        self.vt = VirusTotalValidator(config.get("vt_api_key")) if config.get("vt_api_key") else None
        self.abuse = AbuseIPDBValidator(config.get("abuse_api_key")) if config.get("abuse_api_key") else None
        
        self.weights = {
            "virustotal": 0.4,
            "abuseipdb": 0.3,
            "whitelist": 0.3
        }
    
    async def validate_ioc(self, ioc: IOC, os_type: str = "windows") -> ValidatedIOC:
        results = []
        
        whitelist_result = self.whitelist.validate(ioc, os_type)
        results.append(whitelist_result)
        
        if whitelist_result.is_whitelisted:
            return ValidatedIOC(
                ioc=ioc,
                final_confidence=0.1,
                verdict="benign",
                validation_results=results,
                reason=whitelist_result.reason
            )
        
        if self.vt and ioc.ioc_type in ["ip", "domain", "md5", "sha1", "sha256", "hash"]:
            try:
                if ioc.ioc_type == "ip":
                    vt_result = await self.vt.check_ip(ioc.value)
                elif ioc.ioc_type == "domain":
                    vt_result = await self.vt.check_domain(ioc.value)
                else:
                    vt_result = await self.vt.check_hash(ioc.value)
                results.append(vt_result)
            except Exception:
                pass
        
        if self.abuse and ioc.ioc_type == "ip":
            try:
                abuse_result = await self.abuse.check_ip(ioc.value)
                results.append(abuse_result)
            except Exception:
                pass
        
        final_score = self._calculate_final_score(results, ioc.confidence)
        verdict = self._determine_verdict(final_score)
        
        return ValidatedIOC(
            ioc=ioc,
            final_confidence=final_score,
            verdict=verdict,
            validation_results=results,
            reason=self._generate_reason(results)
        )
    
    def _calculate_final_score(self, results: List[ValidationResult], base_confidence: float) -> float:
        if not results:
            return base_confidence
        
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for result in results:
            weight = self.weights.get(result.source, 0.2)
            weighted_sum += result.score * weight
            weight_sum += weight
        
        if weight_sum > 0:
            return weighted_sum / weight_sum
        return base_confidence
    
    def _determine_verdict(self, score: float) -> str:
        if score >= 0.7:
            return "malicious"
        elif score >= 0.4:
            return "suspicious"
        else:
            return "benign"
    
    def _generate_reason(self, results: List[ValidationResult]) -> str:
        reasons = [r.reason for r in results if r.reason]
        return " | ".join(reasons) if reasons else "No validation data"
    
    async def validate_batch(
        self,
        iocs: List[IOC],
        os_type: str = "windows",
        max_concurrent: int = 5
    ) -> List[ValidatedIOC]:
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def validate_with_semaphore(ioc: IOC) -> ValidatedIOC:
            async with semaphore:
                return await self.validate_ioc(ioc, os_type)
        
        tasks = [validate_with_semaphore(ioc) for ioc in iocs]
        return await asyncio.gather(*tasks)
    
    async def close(self):
        if self.vt:
            await self.vt.close()
        if self.abuse:
            await self.abuse.close()