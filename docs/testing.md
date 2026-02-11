# Testing Guide

## Overview

Testing strategy cho Volatility3 IOC Extraction System bao gồm unit tests, integration tests, và end-to-end tests.

## Test Structure

```
tests/
├── __init__.py
├── conftest.py
├── unit/
│   ├── __init__.py
│   ├── test_decision_engine.py
│   ├── test_ioc_extractor.py
│   ├── test_validator.py
│   ├── test_mitre_mapper.py
│   └── test_report_generator.py
├── integration/
│   ├── __init__.py
│   ├── test_mcp_server.py
│   ├── test_volatility_executor.py
│   └── test_pipeline.py
├── e2e/
│   ├── __init__.py
│   └── test_full_analysis.py
└── fixtures/
    ├── sample_outputs/
    │   ├── pslist_windows.json
    │   ├── malfind_windows.json
    │   └── bash_linux.json
    └── expected/
        ├── iocs_extracted.json
        └── report_sample.json
```

## Configuration

### conftest.py

```python
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def sample_pslist_data():
    return [
        {
            "PID": 4,
            "PPID": 0,
            "ImageFileName": "System",
            "CreateTime": "2026-01-28 10:00:00"
        },
        {
            "PID": 1234,
            "PPID": 456,
            "ImageFileName": "malware.exe",
            "CreateTime": "2026-01-28 12:30:00"
        },
        {
            "PID": 5678,
            "PPID": 1234,
            "ImageFileName": "cmd.exe",
            "CreateTime": "2026-01-28 12:31:00"
        }
    ]

@pytest.fixture
def sample_malfind_data():
    return [
        {
            "PID": 1234,
            "Process": "malware.exe",
            "Start VPN": "0x7ff00000",
            "End VPN": "0x7ff10000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Hexdump": "4D5A9000...",
            "Disasm": "push ebp; mov ebp, esp"
        }
    ]

@pytest.fixture
def sample_cmdline_data():
    return [
        {
            "PID": 5678,
            "ImageFileName": "powershell.exe",
            "Args": "powershell.exe -enc JABjAGwAaQBlAG4AdAA="
        },
        {
            "PID": 9999,
            "ImageFileName": "cmd.exe",
            "Args": "cmd.exe /c whoami"
        }
    ]

@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get.return_value = None
    redis.setex.return_value = True
    return redis

@pytest.fixture
def mock_volatility_executor():
    executor = AsyncMock()
    executor.run.return_value = {
        "success": True,
        "data": [],
        "error": None
    }
    return executor
```

## Unit Tests

### test_decision_engine.py

```python
import pytest
from src.core.decision_engine import DecisionEngine, get_triage_plan

class TestDecisionEngine:
    
    def test_get_triage_plan_malware_windows(self):
        plan = get_triage_plan("windows", "malware_detection")
        
        assert plan.goal == "malware_detection"
        assert plan.os_type == "windows"
        assert "windows.pslist" in [p[0] for p in plan.plugins]
        assert "windows.malware.malfind" in [p[0] for p in plan.plugins]
        assert plan.estimated_minutes > 0
    
    def test_get_triage_plan_malware_linux(self):
        plan = get_triage_plan("linux", "malware_detection")
        
        assert plan.os_type == "linux"
        assert "linux.pslist" in [p[0] for p in plan.plugins]
        assert "linux.malware.malfind" in [p[0] for p in plan.plugins]
    
    def test_get_triage_plan_quick_triage(self):
        plan = get_triage_plan("windows", "quick_triage")
        
        assert plan.estimated_minutes < 10
        assert len(plan.plugins) < 5
    
    def test_get_triage_plan_invalid_goal(self):
        with pytest.raises(ValueError):
            get_triage_plan("windows", "invalid_goal")
    
    def test_get_triage_plan_invalid_os(self):
        with pytest.raises(ValueError):
            get_triage_plan("macos", "malware_detection")
    
    def test_plugin_order_dependencies(self):
        plan = get_triage_plan("windows", "malware_detection")
        plugins = [p[0] for p in plan.plugins]
        
        pslist_idx = plugins.index("windows.pslist")
        if "windows.cmdline" in plugins:
            cmdline_idx = plugins.index("windows.cmdline")
            assert pslist_idx < cmdline_idx
```

### test_ioc_extractor.py

```python
import pytest
from datetime import datetime
from src.core.ioc_extractor import IOCExtractor, ContextAwareExtractor, ExtractionPipeline
from src.models.ioc import IOC

class TestIOCExtractor:
    
    def test_extract_ipv4(self):
        extractor = IOCExtractor()
        text = "Connection to 192.0.2.100:443 established"
        
        iocs = extractor.extract_from_text(text, "test")
        
        ips = [i for i in iocs if i.ioc_type == "ip"]
        assert len(ips) == 1
        assert ips[0].value == "192.0.2.100"
    
    def test_exclude_private_ip(self):
        extractor = IOCExtractor()
        text = "Local connection to 192.168.1.1 and 10.0.0.1"
        
        iocs = extractor.extract_from_text(text, "test")
        
        ips = [i for i in iocs if i.ioc_type == "ip"]
        assert len(ips) == 0
    
    def test_extract_domain(self):
        extractor = IOCExtractor()
        text = "Connecting to evil.malware.com"
        
        iocs = extractor.extract_from_text(text, "test")
        
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert len(domains) == 1
        assert domains[0].value == "evil.malware.com"
    
    def test_exclude_known_domains(self):
        extractor = IOCExtractor()
        text = "Request to www.google.com and api.microsoft.com"
        
        iocs = extractor.extract_from_text(text, "test")
        
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert len(domains) == 0
    
    def test_extract_md5(self):
        extractor = IOCExtractor()
        text = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        
        iocs = extractor.extract_from_text(text, "test")
        
        hashes = [i for i in iocs if i.ioc_type == "md5"]
        assert len(hashes) == 1
    
    def test_extract_sha256(self):
        extractor = IOCExtractor()
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        iocs = extractor.extract_from_text(text, "test")
        
        hashes = [i for i in iocs if i.ioc_type == "sha256"]
        assert len(hashes) == 1
    
    def test_extract_windows_path(self):
        extractor = IOCExtractor()
        text = "Executable at C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe"
        
        iocs = extractor.extract_from_text(text, "test")
        
        paths = [i for i in iocs if i.ioc_type == "filepath"]
        assert len(paths) == 1
    
    def test_extract_registry(self):
        extractor = IOCExtractor()
        text = "Registry key HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        
        iocs = extractor.extract_from_text(text, "test")
        
        registry = [i for i in iocs if i.ioc_type == "registry"]
        assert len(registry) == 1
    
    def test_deduplication(self):
        extractor = IOCExtractor()
        text = "IP 192.0.2.100 and again 192.0.2.100"
        
        iocs = extractor.extract_from_text(text, "test")
        
        ips = [i for i in iocs if i.ioc_type == "ip"]
        assert len(ips) == 1


class TestContextAwareExtractor:
    
    def test_suspicious_parent_child_windows(self, sample_pslist_data):
        extractor = ContextAwareExtractor("windows")
        
        sample_pslist_data.append({
            "PID": 100,
            "PPID": 0,
            "ImageFileName": "winword.exe"
        })
        sample_pslist_data.append({
            "PID": 101,
            "PPID": 100,
            "ImageFileName": "cmd.exe"
        })
        
        iocs = extractor.analyze_processes(sample_pslist_data, [])
        
        process_iocs = [i for i in iocs if i.ioc_type == "process"]
        assert any("winword" in i.value.lower() for i in process_iocs)
    
    def test_encoded_powershell_detection(self, sample_cmdline_data):
        extractor = ContextAwareExtractor("windows")
        
        iocs = extractor.analyze_cmdlines(sample_cmdline_data)
        
        assert len(iocs) > 0
        assert any(i.context.get("pattern_name") == "encoded_powershell" for i in iocs)
    
    def test_malfind_injection_detection(self, sample_malfind_data):
        extractor = ContextAwareExtractor("windows")
        
        iocs = extractor.analyze_malfind(sample_malfind_data)
        
        assert len(iocs) == 1
        assert iocs[0].ioc_type == "injection"
        assert iocs[0].context.get("technique") == "T1055"
        assert iocs[0].context.get("has_pe_header") == True
    
    def test_linux_webshell_detection(self):
        extractor = ContextAwareExtractor("linux")
        
        pslist_data = [
            {"PID": 1, "PPID": 0, "ImageFileName": "nginx"},
            {"PID": 100, "PPID": 1, "ImageFileName": "bash"}
        ]
        
        iocs = extractor.analyze_processes(pslist_data, [])
        
        assert any(i.context.get("technique") == "T1505.003" for i in iocs)
```

### test_validator.py

```python
import pytest
from unittest.mock import AsyncMock, patch
from src.core.validator import (
    WhitelistValidator, 
    VirusTotalValidator, 
    AbuseIPDBValidator,
    ValidationPipeline
)
from src.models.ioc import IOC

class TestWhitelistValidator:
    
    def test_whitelist_google_dns(self):
        validator = WhitelistValidator()
        
        is_whitelisted, reason = validator.check_ip("8.8.8.8")
        
        assert is_whitelisted == True
        assert "safe" in reason.lower()
    
    def test_whitelist_private_ip(self):
        validator = WhitelistValidator()
        
        is_whitelisted, reason = validator.check_ip("192.168.1.100")
        
        assert is_whitelisted == True
        assert "private" in reason.lower()
    
    def test_not_whitelisted_ip(self):
        validator = WhitelistValidator()
        
        is_whitelisted, reason = validator.check_ip("192.0.2.100")
        
        assert is_whitelisted == False
    
    def test_whitelist_microsoft_domain(self):
        validator = WhitelistValidator()
        
        is_whitelisted, reason = validator.check_domain("update.microsoft.com")
        
        assert is_whitelisted == True
    
    def test_whitelist_system_process(self):
        validator = WhitelistValidator()
        
        is_whitelisted, reason = validator.check_process(
            "C:\\Windows\\System32\\svchost.exe",
            "windows"
        )
        
        assert is_whitelisted == True


class TestVirusTotalValidator:
    
    @pytest.mark.asyncio
    async def test_check_ip_malicious(self, mock_redis):
        with patch('src.core.validator.redis', mock_redis):
            validator = VirusTotalValidator("fake_api_key")
            validator._request = AsyncMock(return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 15,
                            "suspicious": 5,
                            "harmless": 50,
                            "undetected": 10
                        }
                    }
                }
            })
            
            result = await validator.check_ip("192.0.2.100")
            
            assert result.is_malicious == True
            assert result.score > 0.3
    
    @pytest.mark.asyncio
    async def test_check_ip_clean(self, mock_redis):
        with patch('src.core.validator.redis', mock_redis):
            validator = VirusTotalValidator("fake_api_key")
            validator._request = AsyncMock(return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 70,
                            "undetected": 10
                        }
                    }
                }
            })
            
            result = await validator.check_ip("1.2.3.4")
            
            assert result.is_malicious == False
            assert result.score < 0.3
    
    @pytest.mark.asyncio
    async def test_check_ip_not_found(self, mock_redis):
        with patch('src.core.validator.redis', mock_redis):
            validator = VirusTotalValidator("fake_api_key")
            validator._request = AsyncMock(return_value=None)
            
            result = await validator.check_ip("1.2.3.4")
            
            assert result.score == 0.5


class TestValidationPipeline:
    
    @pytest.mark.asyncio
    async def test_validate_whitelisted_ioc(self):
        config = {"vt_api_key": None, "abuse_api_key": None}
        pipeline = ValidationPipeline(config)
        
        ioc = IOC(
            ioc_type="ip",
            value="8.8.8.8",
            confidence=0.5,
            source_plugin="test",
            context={},
            extracted_at=datetime.now()
        )
        
        result = await pipeline.validate_ioc(ioc)
        
        assert result.verdict == "benign"
        assert result.final_confidence < 0.2
    
    @pytest.mark.asyncio
    async def test_confidence_calculation(self):
        config = {"vt_api_key": "fake", "abuse_api_key": "fake"}
        pipeline = ValidationPipeline(config)
        
        pipeline.vt = AsyncMock()
        pipeline.vt.check_ip = AsyncMock(return_value=ValidationResult(
            source="virustotal",
            is_malicious=True,
            score=0.8,
            reason="VT: 20/70 malicious"
        ))
        
        pipeline.abuse = AsyncMock()
        pipeline.abuse.check_ip = AsyncMock(return_value=ValidationResult(
            source="abuseipdb",
            is_malicious=True,
            score=0.7,
            reason="AbuseIPDB: 70% confidence"
        ))
        
        ioc = IOC(
            ioc_type="ip",
            value="192.0.2.100",
            confidence=0.5,
            source_plugin="test",
            context={},
            extracted_at=datetime.now()
        )
        
        result = await pipeline.validate_ioc(ioc)
        
        expected_score = (0.8 * 0.4) + (0.7 * 0.3) + (0.5 * 0.3)
        assert abs(result.final_confidence - expected_score) < 0.01
```

### test_mitre_mapper.py

```python
import pytest
from src.core.mitre_mapper import MITREMapper
from src.models.ioc import IOC, ValidatedIOC

class TestMITREMapper:
    
    def test_map_injection_technique(self):
        mapper = MITREMapper()
        
        ioc = IOC(
            ioc_type="injection",
            value="PID 1234",
            confidence=0.9,
            source_plugin="malfind",
            context={"technique": "T1055"},
            extracted_at=datetime.now()
        )
        validated = ValidatedIOC(
            ioc=ioc,
            final_confidence=0.9,
            verdict="malicious",
            validation_results=[],
            reason=""
        )
        
        report = mapper.map_iocs([validated])
        
        assert "T1055" in report.techniques
        assert report.techniques["T1055"]["technique"]["name"] == "Process Injection"
    
    def test_map_multiple_techniques(self):
        mapper = MITREMapper()
        
        iocs = [
            ValidatedIOC(
                ioc=IOC(
                    ioc_type="injection",
                    value="PID 1234",
                    confidence=0.9,
                    source_plugin="malfind",
                    context={"technique": "T1055"},
                    extracted_at=datetime.now()
                ),
                final_confidence=0.9,
                verdict="malicious",
                validation_results=[],
                reason=""
            ),
            ValidatedIOC(
                ioc=IOC(
                    ioc_type="command",
                    value="powershell -enc",
                    confidence=0.85,
                    source_plugin="cmdline",
                    context={"technique": "T1059.001"},
                    extracted_at=datetime.now()
                ),
                final_confidence=0.85,
                verdict="malicious",
                validation_results=[],
                reason=""
            )
        ]
        
        report = mapper.map_iocs(iocs)
        
        assert report.total_techniques == 2
        assert "T1055" in report.techniques
        assert "T1059.001" in report.techniques
    
    def test_skip_benign_iocs(self):
        mapper = MITREMapper()
        
        ioc = ValidatedIOC(
            ioc=IOC(
                ioc_type="ip",
                value="8.8.8.8",
                confidence=0.1,
                source_plugin="network",
                context={"technique": "T1071"},
                extracted_at=datetime.now()
            ),
            final_confidence=0.1,
            verdict="benign",
            validation_results=[],
            reason=""
        )
        
        report = mapper.map_iocs([ioc])
        
        assert report.total_techniques == 0
    
    def test_generate_matrix(self):
        mapper = MITREMapper()
        
        iocs = [
            ValidatedIOC(
                ioc=IOC(
                    ioc_type="injection",
                    value="PID 1234",
                    confidence=0.9,
                    source_plugin="malfind",
                    context={"technique": "T1055"},
                    extracted_at=datetime.now()
                ),
                final_confidence=0.9,
                verdict="malicious",
                validation_results=[],
                reason=""
            )
        ]
        
        report = mapper.map_iocs(iocs)
        matrix = mapper.generate_matrix(report)
        
        assert "Defense Evasion" in matrix
        assert len(matrix["Defense Evasion"]) > 0
```

## Integration Tests

### test_mcp_server.py

```python
import pytest
from unittest.mock import AsyncMock, patch
from src.mcp_server.server import mcp

class TestMCPServer:
    
    @pytest.mark.asyncio
    async def test_smart_triage_tool(self):
        with patch('src.mcp_server.tools.triage.validate_dump_path'):
            with patch('src.mcp_server.tools.triage.detect_os') as mock_detect:
                mock_detect.return_value = AsyncMock(
                    os_type="windows",
                    version="10",
                    arch="x64"
                )
                
                result = await mcp.call_tool(
                    "smart_triage",
                    {"dump_path": "/app/data/dumps/test.raw"}
                )
                
                assert "case_id" in result
                assert "plan" in result
                assert result["os"]["type"] == "windows"
    
    @pytest.mark.asyncio
    async def test_extract_iocs_tool(self):
        plugin_results = {
            "data": {
                "windows.pslist": {
                    "success": True,
                    "data": [{"PID": 1234, "ImageFileName": "test.exe"}]
                }
            }
        }
        
        result = await mcp.call_tool(
            "extract_iocs",
            {"plugin_results": plugin_results, "os_type": "windows"}
        )
        
        assert "total" in result
        assert "iocs" in result
    
    @pytest.mark.asyncio
    async def test_resource_plugins_catalog(self):
        result = await mcp.read_resource("plugins://catalog")
        
        assert "windows" in result
        assert "linux" in result


class TestMCPToolValidation:
    
    @pytest.mark.asyncio
    async def test_invalid_dump_path(self):
        with pytest.raises(Exception):
            await mcp.call_tool(
                "smart_triage",
                {"dump_path": "/etc/passwd"}
            )
    
    @pytest.mark.asyncio
    async def test_invalid_goal(self):
        with patch('src.mcp_server.tools.triage.validate_dump_path'):
            with pytest.raises(ValueError):
                await mcp.call_tool(
                    "smart_triage",
                    {"dump_path": "/app/data/dumps/test.raw", "goal": "invalid"}
                )
```

### test_pipeline.py

```python
import pytest
from unittest.mock import AsyncMock, patch
from src.core.pipeline import AnalysisPipeline

class TestAnalysisPipeline:
    
    @pytest.mark.asyncio
    async def test_full_pipeline_windows(self):
        pipeline = AnalysisPipeline()
        
        with patch.object(pipeline, 'detect_os') as mock_os:
            mock_os.return_value = {"os_type": "windows", "version": "10"}
            
            with patch.object(pipeline, 'execute_plugins') as mock_exec:
                mock_exec.return_value = {
                    "windows.pslist": {"success": True, "data": []},
                    "windows.malware.malfind": {"success": True, "data": []}
                }
                
                with patch.object(pipeline, 'extract_iocs') as mock_extract:
                    mock_extract.return_value = []
                    
                    with patch.object(pipeline, 'validate_iocs') as mock_validate:
                        mock_validate.return_value = []
                        
                        result = await pipeline.run(
                            "/app/data/dumps/test.raw",
                            "malware_detection"
                        )
                        
                        assert result["status"] == "completed"
                        mock_os.assert_called_once()
                        mock_exec.assert_called_once()
```

## Running Tests

### All Tests

```bash
pytest tests/ -v
```

### Unit Tests Only

```bash
pytest tests/unit/ -v
```

### Integration Tests

```bash
pytest tests/integration/ -v
```

### With Coverage

```bash
pytest tests/ --cov=src --cov-report=html
```

### Specific Test File

```bash
pytest tests/unit/test_ioc_extractor.py -v
```

### Specific Test

```bash
pytest tests/unit/test_ioc_extractor.py::TestIOCExtractor::test_extract_ipv4 -v
```

## Test Fixtures

### Sample Plugin Outputs

```json
// fixtures/sample_outputs/pslist_windows.json
[
  {
    "PID": 4,
    "PPID": 0,
    "ImageFileName": "System",
    "Offset": "0x8a0f1040",
    "Threads": 120,
    "Handles": 1500,
    "SessionId": 0,
    "Wow64": false,
    "CreateTime": "2026-01-28 10:00:00",
    "ExitTime": null
  },
  {
    "PID": 1234,
    "PPID": 456,
    "ImageFileName": "malware.exe",
    "Offset": "0x8a0f2080",
    "Threads": 5,
    "Handles": 100,
    "SessionId": 1,
    "Wow64": false,
    "CreateTime": "2026-01-28 12:30:00",
    "ExitTime": null
  }
]
```

```json
// fixtures/sample_outputs/malfind_windows.json
[
  {
    "PID": 1234,
    "Process": "malware.exe",
    "Start VPN": "0x7ff00000",
    "End VPN": "0x7ff10000",
    "Tag": "VadS",
    "Protection": "PAGE_EXECUTE_READWRITE",
    "CommitCharge": 16,
    "PrivateMemory": 1,
    "Hexdump": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
    "Disasm": "dec ebp; pop edx; nop; add byte ptr [ebx], al"
  }
]
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov
      
      - name: Run tests
        run: pytest tests/ -v --cov=src --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.xml
```