import sys
import aiohttp
import asyncio
import json
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from src.models.ioc import IOC, ValidatedIOC, ValidationResult

@dataclass
class DeepSeekAnalysis:
    verdict: str
    confidence: float
    reasoning: str
    threat_type: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)

class DeepSeekValidator:
    BASE_URL = "https://api.deepseek.com/v1"
    
    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        self.api_key = api_key
        self.model = model
        self.session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, DeepSeekAnalysis] = {}
        self._semaphore = asyncio.Semaphore(3)
        self.total_tokens = 0
        self.total_requests = 0
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self.session
    
    def _cache_key(self, ioc: IOC) -> str:
        data = f"{ioc.ioc_type}:{ioc.value}:{ioc.context.get('protection', '')}:{ioc.context.get('pid', '')}"
        return hashlib.md5(data.encode()).hexdigest()
    
    async def analyze_batch(self, iocs: List[IOC], max_batch: int = 20) -> List[DeepSeekAnalysis]:
        if not iocs:
            return []
        
        results = []
        uncached_iocs = []
        uncached_indices = []
        
        for i, ioc in enumerate(iocs):
            cache_key = self._cache_key(ioc)
            if cache_key in self._cache:
                results.append((i, self._cache[cache_key]))
            else:
                uncached_iocs.append(ioc)
                uncached_indices.append(i)
        
        if uncached_iocs:
            batches = [uncached_iocs[i:i + max_batch] for i in range(0, len(uncached_iocs), max_batch)]
            
            for batch in batches:
                async with self._semaphore:
                    batch_results = await self._analyze_single_batch(batch)
                    for ioc, analysis in zip(batch, batch_results):
                        self._cache[self._cache_key(ioc)] = analysis
                    results.extend([(uncached_indices[len(results) - len([r for r in results if isinstance(r[1], DeepSeekAnalysis)]) + i], r) for i, r in enumerate(batch_results)])
                    await asyncio.sleep(0.5)
        
        sorted_results = [None] * len(iocs)
        for idx, analysis in results:
            sorted_results[idx] = analysis
        
        return [r if r else self._fallback_result(iocs[i]) for i, r in enumerate(sorted_results)]
    
    async def _analyze_single_batch(self, iocs: List[IOC]) -> List[DeepSeekAnalysis]:
        prompt = self._build_prompt(iocs)
        
        max_tokens_for_batch = min(1000, len(iocs) * 50 + 100)
        
        for attempt in range(3):
            try:
                session = await self._get_session()
                
                async with session.post(
                    f"{self.BASE_URL}/chat/completions",
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "Analyst. JSON only: {\"iocs\":[{\"v\":\"malicious|suspicious|benign\",\"c\":0.5,\"r\":\"5 words max\"}]}. v=verdict, c=confidence, r=reason. MUST be under 5 words per reason."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0,
                        "max_tokens": 50,
                        "stop": ["\n\n", "reasoning:", "explanation:"],
                        "response_format": {"type": "json_object"}
                    }
                ) as response:
                    self.total_requests += 1
                    
                    if response.status == 429:
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                        continue
                    
                    if response.status != 200:
                        error_text = await response.text()
                        if attempt == 2:
                            print(f"DeepSeek HTTP {response.status}: {error_text[:100]}", file=sys.stderr)
                            return [self._fallback_result(ioc) for ioc in iocs]
                        continue
                    
                    result = await response.json()
                    
                    if "usage" in result:
                        usage = result["usage"]
                        self.total_tokens += usage.get("total_tokens", 0)
                        print(
                            f"[DeepSeek] In: {usage.get('prompt_tokens', 0)}"
                            f" (cache_hit: {usage.get('prompt_cache_hit_tokens', 0)},"
                            f" miss: {usage.get('prompt_cache_miss_tokens', 0)}),"
                            f" Out: {usage.get('completion_tokens', 0)}",
                            file=sys.stderr,
                        )
                    
                    content = result["choices"][0]["message"]["content"].strip()
                    
                    if content.startswith("```json"):
                        content = content[7:]
                    if content.endswith("```"):
                        content = content[:-3]
                    content = content.strip()
                    
                    parsed = json.loads(content)
                    analyses = parsed.get("iocs", [])
                    
                    return [
                        DeepSeekAnalysis(
                            verdict=a.get("v") or a.get("verdict", "suspicious"),
                            confidence=float(a.get("c") or a.get("confidence", 0.5)),
                            reasoning=(a.get("r") or a.get("reasoning", ""))[:50],
                            threat_type=a.get("threat_type"),
                            mitre_techniques=a.get("mitre_techniques", [])
                        )
                        for a in analyses[:len(iocs)]
                    ] + [self._fallback_result(iocs[i]) for i in range(len(analyses), len(iocs))]
            
            except json.JSONDecodeError:
                if attempt == 2:
                    return [self._fallback_result(ioc) for ioc in iocs]
                await asyncio.sleep(1)
                continue
            
            except asyncio.TimeoutError:
                if attempt == 2:
                    return [self._fallback_result(ioc) for ioc in iocs]
                continue
            
            except Exception as e:
                if attempt == 2:
                    print(f"DeepSeek error: {type(e, file=sys.stderr).__name__}")
                    return [self._fallback_result(ioc) for ioc in iocs]
                await asyncio.sleep(2 ** attempt)
        
        return [self._fallback_result(ioc) for ioc in iocs]
    
    def _build_prompt(self, iocs: List[IOC]) -> str:
        lines = [f"{len(iocs)} IOCs:\n"]
        
        for i, ioc in enumerate(iocs[:20], 1):
            line = f"{i}.{ioc.ioc_type}:{ioc.value}"
            
            if ioc.context.get("protection"):
                line += f"|{ioc.context['protection']}"
            
            lines.append(line)
        
        return "\n".join(lines)
    
    def _fallback_result(self, ioc: IOC) -> DeepSeekAnalysis:
        verdict = "malicious" if ioc.ioc_type == "injection" else "suspicious"
        confidence = max(0.8, ioc.confidence) if ioc.ioc_type == "injection" else ioc.confidence
        
        return DeepSeekAnalysis(
            verdict=verdict,
            confidence=confidence,
            reasoning="Local analysis only"
        )
    
    async def close(self):
        """Close the underlying aiohttp session."""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception:
                pass
        self.session = None

class HybridValidator:
    def __init__(self, config: Dict[str, Any]):
        self.deepseek = DeepSeekValidator(config["deepseek_api_key"]) if config.get("deepseek_api_key") else None
        self.use_local = config.get("use_local_patterns", True)
    
    async def validate_batch(self, iocs: List[IOC], os_type: str = "windows") -> List[ValidatedIOC]:
        if not iocs:
            return []
        
        by_pid = {}
        for ioc in iocs:
            pid = ioc.context.get("pid")
            if pid:
                by_pid.setdefault(pid, []).append(ioc)
        
        results = []
        
        if self.deepseek:
            deepseek_analyses = await self.deepseek.analyze_batch(iocs)
            
            for ioc, analysis in zip(iocs, deepseek_analyses):
                local_score = self._local_score(ioc)
                
                pid = ioc.context.get("pid")
                if pid and len(by_pid.get(pid, [])) > 3:
                    local_score = min(1.0, local_score + 0.15)
                
                final_confidence = (local_score * 0.3) + (analysis.confidence * 0.7)
                
                if final_confidence >= 0.7:
                    verdict = "malicious"
                elif final_confidence >= 0.4:
                    verdict = "suspicious"
                else:
                    verdict = "benign"
                
                results.append(ValidatedIOC(
                    ioc=ioc,
                    final_confidence=final_confidence,
                    verdict=verdict,
                    validation_results=[
                        ValidationResult(
                            source="deepseek",
                            is_malicious=analysis.verdict == "malicious",
                            score=analysis.confidence,
                            reason=analysis.reasoning[:100],
                            metadata={
                                "threat_type": analysis.threat_type,
                                "mitre": analysis.mitre_techniques
                            }
                        ),
                        ValidationResult(
                            source="local_patterns",
                            is_malicious=local_score > 0.7,
                            score=local_score,
                            reason="Pattern-based",
                            metadata={}
                        )
                    ],
                    reason=analysis.reasoning[:100]
                ))
        else:
            for ioc in iocs:
                local_score = self._local_score(ioc)
                results.append(ValidatedIOC(
                    ioc=ioc,
                    final_confidence=local_score,
                    verdict="suspicious" if local_score > 0.5 else "benign",
                    validation_results=[
                        ValidationResult(
                            source="local_patterns",
                            is_malicious=local_score > 0.7,
                            score=local_score,
                            reason="Local only",
                            metadata={}
                        )
                    ],
                    reason="Local analysis"
                ))
        
        if self.deepseek:
            print(f"\nDeepSeek Total: {self.deepseek.total_requests} requests, {self.deepseek.total_tokens} tokens", file=sys.stderr)
        
        return results
    
    def _local_score(self, ioc: IOC) -> float:
        score = 0.5
        ctx = ioc.context
        
        if ioc.ioc_type == "injection":
            score += 0.4
            if ctx.get("hexdump") and any(p in str(ctx["hexdump"]) for p in ["\\xfc\\xe8", "kernel32"]):
                score += 0.2
        
        if "PAGE_EXECUTE_READWRITE" in ctx.get("protection", ""):
            score += 0.3
        
        process = ctx.get("process", "").lower()
        if any(p in process for p in ["powershell", "cmd", "rundll32", "regsvr32"]):
            score += 0.15
        
        cmdline = ctx.get("cmdline", "").lower()
        if any(x in cmdline for x in ["-enc", "-nop", "hidden", "bypass"]):
            score += 0.25
        
        if ioc.ioc_type == "ip" and not ioc.value.startswith(("10.", "172.16.", "192.168.", "127.")):
            score += 0.2
        
        if ioc.ioc_type == "filepath" and any(x in ioc.value.lower() for x in ["temp", "appdata\\local"]):
            score += 0.15
        
        return min(1.0, score)
    
    async def close(self):
        if self.deepseek:
            await self.deepseek.close()
