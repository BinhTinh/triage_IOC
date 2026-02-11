# Phase 4: Validation & Enrichment

## Overview

Phase 4 validates extracted IOCs against threat intelligence sources to filter false positives and assign confidence scores.

## Components

### 4.1 Validation Sources

| Source | Type | Rate Limit | Cache TTL | Weight |
|--------|------|------------|-----------|--------|
| VirusTotal | API | 4/min (free) | 6 hours | 40% |
| AbuseIPDB | API | 1000/day | 6 hours | 30% |
| Local Whitelist | File | N/A | Permanent | 30% |

### 4.2 Local Whitelist

```yaml
whitelist:
  ips:
    - value: "8.8.8.8"
      reason: "Google Public DNS"
    - value: "8.8.4.4"
      reason: "Google Public DNS"
    - value: "1.1.1.1"
      reason: "Cloudflare DNS"
    - value: "1.0.0.1"
      reason: "Cloudflare DNS"
    - value: "208.67.222.222"
      reason: "OpenDNS"
    - value: "208.67.220.220"
      reason: "OpenDNS"
    
  ip_ranges:
    - range: "10.0.0.0/8"
      reason: "Private network"
    - range: "172.16.0.0/12"
      reason: "Private network"
    - range: "192.168.0.0/16"
      reason: "Private network"
    - range: "127.0.0.0/8"
      reason: "Loopback"
    - range: "169.254.0.0/16"
      reason: "Link-local"
    
  domains:
    - pattern: "*.microsoft.com"
      reason: "Microsoft"
    - pattern: "*.windows.com"
      reason: "Microsoft"
    - pattern: "*.windowsupdate.com"
      reason: "Windows Update"
    - pattern: "*.google.com"
      reason: "Google"
    - pattern: "*.googleapis.com"
      reason: "Google APIs"
    - pattern: "*.gstatic.com"
      reason: "Google Static"
    - pattern: "*.amazonaws.com"
      reason: "AWS"
    - pattern: "*.cloudflare.com"
      reason: "Cloudflare"
    
  processes:
    windows:
      - path: "C:\\Windows\\System32\\svchost.exe"
        reason: "Windows Service Host"
      - path: "C:\\Windows\\System32\\csrss.exe"
        reason: "Client/Server Runtime"
      - path: "C:\\Windows\\System32\\smss.exe"
        reason: "Session Manager"
      - path: "C:\\Windows\\System32\\wininit.exe"
        reason: "Windows Initialization"
      - path: "C:\\Windows\\System32\\services.exe"
        reason: "Service Control Manager"
      - path: "C:\\Windows\\System32\\lsass.exe"
        reason: "Local Security Authority"
      - path: "C:\\Windows\\explorer.exe"
        reason: "Windows Explorer"
    linux:
      - path: "/sbin/init"
        reason: "Init process"
      - path: "/usr/lib/systemd/systemd"
        reason: "Systemd"
      - path: "/usr/sbin/sshd"
        reason: "SSH Daemon"
      - path: "/usr/sbin/cron"
        reason: "Cron Daemon"
    
  hashes:
    - value: "d41d8cd98f00b204e9800998ecf8427e"
      reason: "Empty file MD5"
    - value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      reason: "Empty file SHA256"
```

### 4.3 Whitelist Validator

```python
class WhitelistValidator:
    def __init__(self, whitelist_path: str = "config/whitelist.yaml"):
        with open(whitelist_path) as f:
            self.whitelist = yaml.safe_load(f)
        
        self.ip_networks = [
            ipaddress.ip_network(r['range'])
            for r in self.whitelist.get('ip_ranges', [])
        ]
        
        self.domain_patterns = [
            re.compile(d['pattern'].replace('*', '.*'))
            for d in self.whitelist.get('domains', [])
        ]
    
    def check_ip(self, ip: str) -> Tuple[bool, str]:
        if ip in [w['value'] for w in self.whitelist.get('ips', [])]:
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
        if hash_value.lower() in [h['value'].lower() for h in self.whitelist.get('hashes', [])]:
            return True, "Known safe hash"
        return False, ""
    
    def check_process(self, path: str, os_type: str) -> Tuple[bool, str]:
        processes = self.whitelist.get('processes', {}).get(os_type, [])
        if path.lower() in [p['path'].lower() for p in processes]:
            return True, "Known system process"
        return False, ""
    
    def validate(self, ioc: IOC, os_type: str = "windows") -> ValidationResult:
        is_whitelisted = False
        reason = ""
        
        if ioc.ioc_type == 'ip':
            is_whitelisted, reason = self.check_ip(ioc.value)
        elif ioc.ioc_type == 'domain':
            is_whitelisted, reason = self.check_domain(ioc.value)
        elif ioc.ioc_type in ['md5', 'sha1', 'sha256', 'hash']:
            is_whitelisted, reason = self.check_hash(ioc.value)
        elif ioc.ioc_type == 'process':
            is_whitelisted, reason = self.check_process(ioc.value, os_type)
        
        return ValidationResult(
            source='whitelist',
            is_malicious=False,
            is_whitelisted=is_whitelisted,
            score=0.0 if is_whitelisted else 0.5,
            reason=reason
        )
```

### 4.4 VirusTotal Validator

```python
class VirusTotalValidator:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
        self.rate_limiter = asyncio.Semaphore(4)
        self.last_request = 0
    
    async def _request(self, endpoint: str) -> dict:
        async with self.rate_limiter:
            now = time.time()
            wait_time = max(0, 15 - (now - self.last_request))
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            headers = {"x-apikey": self.api_key}
            url = f"{self.BASE_URL}/{endpoint}"
            
            async with self.session.get(url, headers=headers) as resp:
                self.last_request = time.time()
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return None
                elif resp.status == 429:
                    raise RateLimitError("VirusTotal rate limit exceeded")
                else:
                    raise APIError(f"VT API error: {resp.status}")
    
    async def check_ip(self, ip: str) -> ValidationResult:
        cache_key = f"vt:ip:{ip}"
        cached = await redis.get(cache_key)
        if cached:
            return ValidationResult.from_json(cached)
        
        data = await self._request(f"ip_addresses/{ip}")
        
        if not data:
            result = ValidationResult(
                source='virustotal',
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        else:
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            
            score = (malicious * 1.0 + suspicious * 0.5) / total
            
            result = ValidationResult(
                source='virustotal',
                is_malicious=score > 0.3,
                score=score,
                reason=f"VT: {malicious}/{total} malicious, {suspicious}/{total} suspicious",
                raw_data=stats
            )
        
        await redis.setex(cache_key, 21600, result.to_json())
        return result
    
    async def check_domain(self, domain: str) -> ValidationResult:
        cache_key = f"vt:domain:{domain}"
        cached = await redis.get(cache_key)
        if cached:
            return ValidationResult.from_json(cached)
        
        data = await self._request(f"domains/{domain}")
        
        if not data:
            result = ValidationResult(
                source='virustotal',
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        else:
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            
            score = (malicious * 1.0 + suspicious * 0.5) / total
            
            result = ValidationResult(
                source='virustotal',
                is_malicious=score > 0.3,
                score=score,
                reason=f"VT: {malicious}/{total} malicious",
                raw_data=stats
            )
        
        await redis.setex(cache_key, 21600, result.to_json())
        return result
    
    async def check_hash(self, hash_value: str) -> ValidationResult:
        cache_key = f"vt:hash:{hash_value}"
        cached = await redis.get(cache_key)
        if cached:
            return ValidationResult.from_json(cached)
        
        data = await self._request(f"files/{hash_value}")
        
        if not data:
            result = ValidationResult(
                source='virustotal',
                is_malicious=False,
                score=0.5,
                reason="Not found in VirusTotal"
            )
        else:
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) or 1
            
            score = malicious / total
            
            result = ValidationResult(
                source='virustotal',
                is_malicious=score > 0.3,
                score=score,
                reason=f"VT: {malicious}/{total} detections",
                raw_data=stats
            )
        
        await redis.setex(cache_key, 21600, result.to_json())
        return result
```

### 4.5 AbuseIPDB Validator

```python
class AbuseIPDBValidator:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
    
    async def check_ip(self, ip: str) -> ValidationResult:
        cache_key = f"abuse:ip:{ip}"
        cached = await redis.get(cache_key)
        if cached:
            return ValidationResult.from_json(cached)
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        
        async with self.session.get(
            f"{self.BASE_URL}/check",
            headers=headers,
            params=params
        ) as resp:
            if resp.status != 200:
                return ValidationResult(
                    source='abuseipdb',
                    is_malicious=False,
                    score=0.5,
                    reason="AbuseIPDB API error"
                )
            
            data = await resp.json()
            abuse_data = data.get('data', {})
            
            confidence = abuse_data.get('abuseConfidencePercentage', 0) / 100
            total_reports = abuse_data.get('totalReports', 0)
            
            result = ValidationResult(
                source='abuseipdb',
                is_malicious=confidence > 0.5,
                score=confidence,
                reason=f"AbuseIPDB: {confidence*100:.0f}% confidence, {total_reports} reports",
                raw_data={
                    'confidence': confidence,
                    'total_reports': total_reports,
                    'country': abuse_data.get('countryCode'),
                    'isp': abuse_data.get('isp')
                }
            )
        
        await redis.setex(cache_key, 21600, result.to_json())
        return result
```

### 4.6 Validation Pipeline

```python
class ValidationPipeline:
    def __init__(self, config: dict):
        self.whitelist = WhitelistValidator()
        self.vt = VirusTotalValidator(config.get('vt_api_key')) if config.get('vt_api_key') else None
        self.abuse = AbuseIPDBValidator(config.get('abuse_api_key')) if config.get('abuse_api_key') else None
        
        self.weights = {
            'virustotal': 0.4,
            'abuseipdb': 0.3,
            'whitelist': 0.3
        }
    
    async def validate_ioc(self, ioc: IOC, os_type: str = "windows") -> ValidatedIOC:
        results = []
        
        whitelist_result = self.whitelist.validate(ioc, os_type)
        results.append(whitelist_result)
        
        if whitelist_result.is_whitelisted:
            return ValidatedIOC(
                ioc=ioc,
                final_confidence=0.1,
                verdict='benign',
                validation_results=results,
                reason=whitelist_result.reason
            )
        
        if self.vt and ioc.ioc_type in ['ip', 'domain', 'md5', 'sha1', 'sha256', 'hash']:
            try:
                if ioc.ioc_type == 'ip':
                    vt_result = await self.vt.check_ip(ioc.value)
                elif ioc.ioc_type == 'domain':
                    vt_result = await self.vt.check_domain(ioc.value)
                else:
                    vt_result = await self.vt.check_hash(ioc.value)
                results.append(vt_result)
            except (RateLimitError, APIError) as e:
                logger.warning(f"VT validation failed: {e}")
        
        if self.abuse and ioc.ioc_type == 'ip':
            try:
                abuse_result = await self.abuse.check_ip(ioc.value)
                results.append(abuse_result)
            except Exception as e:
                logger.warning(f"AbuseIPDB validation failed: {e}")
        
        final_score = self._calculate_final_score(results)
        verdict = self._determine_verdict(final_score)
        
        return ValidatedIOC(
            ioc=ioc,
            final_confidence=final_score,
            verdict=verdict,
            validation_results=results,
            reason=self._generate_reason(results)
        )
    
    def _calculate_final_score(self, results: List[ValidationResult]) -> float:
        if not results:
            return 0.5
        
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for result in results:
            weight = self.weights.get(result.source, 0.2)
            weighted_sum += result.score * weight
            weight_sum += weight
        
        return weighted_sum / weight_sum if weight_sum > 0 else 0.5
    
    def _determine_verdict(self, score: float) -> str:
        if score >= 0.7:
            return 'malicious'
        elif score >= 0.4:
            return 'suspicious'
        else:
            return 'benign'
    
    def _generate_reason(self, results: List[ValidationResult]) -> str:
        reasons = [r.reason for r in results if r.reason]
        return " | ".join(reasons)
    
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
```

## MCP Tool: validate_iocs

```python
@mcp.tool()
async def validate_iocs(
    iocs: List[dict],
    os_type: str = "windows"
) -> dict:
    """
    Validate IOCs against threat intelligence sources.
    
    Args:
        iocs: List of IOCs from extract_iocs tool
        os_type: Operating system type
    
    Returns:
        Validated IOCs with verdicts and confidence scores
    """
    config = {
        'vt_api_key': os.getenv('VT_API_KEY'),
        'abuse_api_key': os.getenv('ABUSEIPDB_KEY')
    }
    
    pipeline = ValidationPipeline(config)
    
    ioc_objects = [
        IOC(
            ioc_type=i['type'],
            value=i['value'],
            confidence=i.get('confidence', 0.5),
            source_plugin=i.get('source', 'unknown'),
            context=i.get('context', {}),
            extracted_at=datetime.fromisoformat(i['extracted_at']) if 'extracted_at' in i else datetime.now()
        )
        for i in iocs
    ]
    
    await ctx.info(f"Validating {len(ioc_objects)} IOCs...")
    validated = await pipeline.validate_batch(ioc_objects, os_type)
    
    by_verdict = {'malicious': [], 'suspicious': [], 'benign': []}
    for v in validated:
        by_verdict[v.verdict].append({
            'type': v.ioc.ioc_type,
            'value': v.ioc.value,
            'confidence': v.final_confidence,
            'verdict': v.verdict,
            'reason': v.reason,
            'context': v.ioc.context
        })
    
    await ctx.info(f"Results: {len(by_verdict['malicious'])} malicious, {len(by_verdict['suspicious'])} suspicious, {len(by_verdict['benign'])} benign")
    
    return {
        "total": len(validated),
        "summary": {
            "malicious": len(by_verdict['malicious']),
            "suspicious": len(by_verdict['suspicious']),
            "benign": len(by_verdict['benign'])
        },
        "malicious": by_verdict['malicious'],
        "suspicious": by_verdict['suspicious'],
        "benign": by_verdict['benign'],
        "next_action": "Call map_mitre to map findings to ATT&CK techniques"
    }
```

## Output Schema

```json
{
  "total": 45,
  "summary": {
    "malicious": 5,
    "suspicious": 12,
    "benign": 28
  },
  "malicious": [
    {
      "type": "ip",
      "value": "192.0.2.100",
      "confidence": 0.85,
      "verdict": "malicious",
      "reason": "VT: 15/70 malicious | AbuseIPDB: 75% confidence, 23 reports",
      "context": {
        "process": "malware.exe",
        "technique": "T1071"
      }
    }
  ],
  "suspicious": [...],
  "benign": [...],
  "next_action": "Call map_mitre to map findings to ATT&CK techniques"
}
```