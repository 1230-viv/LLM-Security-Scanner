# Design Document: LLM Security Scanner

## Overview

The LLM Security Scanner is a production-ready, modular security testing platform designed to detect vulnerabilities in LLM-based applications through automated red-teaming. The system executes curated attack prompts against target endpoints, analyzes responses using rule-based and LLM-based detection, and generates actionable vulnerability reports.

The architecture follows a plugin-based design pattern enabling future extensibility without core modifications. The MVP implements three core vulnerability detection categories: prompt injection, jailbreaking, and data leakage.

### Design Principles

1. **Modularity**: Clear separation of concerns with well-defined interfaces
2. **Extensibility**: Plugin architecture for adding new detectors and evaluators
3. **Asynchronicity**: Non-blocking scan execution for high throughput
4. **Security-First**: Secure credential handling and input validation
5. **Production-Ready**: Fault tolerance, error handling, and scalability

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                              │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐     │
│  │   CLI    │    │   REST API   │    │   Web Dashboard  │     │
│  └────┬─────┘    └──────┬───────┘    └────────┬─────────┘     │
└───────┼──────────────────┼──────────────────────┼───────────────┘
        │                  │                      │
        └──────────────────┼──────────────────────┘
                           │
┌──────────────────────────┼───────────────────────────────────────┐
│                    API Layer (FastAPI)                            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Request Validation │ Authentication │ Rate Limiting    │    │
│  └─────────────────────────────────────────────────────────┘    │
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────┼───────────────────────────────────────┐
│                    Scanner Engine (Core)                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Scan Orchestrator │ Plugin Manager │ Config Manager    │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────┬───────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────┴────────┐  ┌────────┴─────────┐  ┌────────┴──────────┐
│ Attack Library │  │ Detection Engine │  │  Report Engine    │
│   - Prompts    │  │  - Detectors     │  │  - Formatters     │
│   - Categories │  │  - Evaluators    │  │  - Templates      │
└────────────────┘  └──────────────────┘  └───────────────────┘
        │                   │                       │
        └───────────────────┼───────────────────────┘
                            │
┌───────────────────────────┼───────────────────────────────────────┐
│                    Data Layer (PostgreSQL)                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Scans │ Vulnerabilities │ Configurations │ Credentials  │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

### Component Interaction Flow

```
1. User initiates scan (CLI/API/UI)
2. API Layer validates input and creates scan record
3. ScanLifecycleManager transitions scan to QUEUED state
4. Scanner Engine loads configuration and attack prompts
5. ScanLifecycleManager transitions scan to RUNNING state
6. Attack Executor sends prompts to target endpoint (async, with concurrency control)
7. Detection Engine analyzes responses using plugins
8. DetectionAggregator merges and normalizes vulnerability findings
9. Report Engine generates prioritized report
10. ScanLifecycleManager transitions scan to COMPLETED/FAILED state
11. Results persisted to database
12. User retrieves report via API/UI
```

### Concurrency Model

**Async Boundaries**:
- API endpoints: Async handlers (FastAPI)
- Scan execution: Background tasks (non-blocking)
- Attack execution: Async HTTP requests with semaphore-based concurrency control
- Detection: Async plugin invocation
- Database operations: Async SQLAlchemy

**Concurrency Limits**:
- Max concurrent scans: Configurable (default: 10)
- Max concurrent requests per scan: Configurable (default: 5)
- Rate limiting: Per-scan and global limits
- Database connection pool: 20 connections

### Technology Stack

- **Backend Framework**: FastAPI (async support, automatic OpenAPI docs)
- **Language**: Python 3.11+
- **Database**: PostgreSQL 15+ (JSONB for flexible vulnerability storage)
- **ORM**: SQLAlchemy 2.0 (async support)
- **HTTP Client**: httpx (async HTTP requests)
- **Task Queue**: FastAPI BackgroundTasks (MVP), Celery-ready architecture
- **Frontend**: React 18 with TypeScript
- **Containerization**: Docker + Docker Compose
- **Testing**: pytest, pytest-asyncio, httpx mock

## Components and Interfaces

### 1. Core Scanner Engine

The Scanner Engine orchestrates all scanning operations and manages the plugin lifecycle.

#### ScanOrchestrator

```python
class ScanOrchestrator:
    """
    Coordinates scan execution across all components.
    """
    
    async def execute_scan(scan_id: str, config: ScanConfig) -> ScanResult:
        """
        Main scan execution flow:
        1. Transition to RUNNING state
        2. Load attack prompts based on config
        3. Execute prompts against target endpoint (with cost tracking)
        4. Collect responses
        5. Run detection plugins on responses
        6. Aggregate and normalize vulnerabilities
        7. Generate prioritized report
        8. Transition to COMPLETED/FAILED state
        
        Aborts if:
        - max_requests exceeded
        - max_tokens exceeded
        - cost_limit exceeded
        """
        
    async def execute_attack_batch(
        prompts: List[AttackPrompt],
        target: TargetConfig
    ) -> List[AttackResponse]:
        """
        Execute a batch of attack prompts with rate limiting and concurrency control.
        """

#### PluginManager

```python
class PluginManager:
    """
    Manages detector and evaluator plugin lifecycle.
    """
    
    def register_detector(detector: DetectorPlugin) -> None:
        """
        Register a detector plugin.
        """
    
    def register_evaluator(evaluator: EvaluatorPlugin) -> None:
        """
        Register an evaluator plugin.
        """
    
    def get_detectors(categories: List[str]) -> List[DetectorPlugin]:
        """
        Retrieve detectors for specified vulnerability categories.
        """
    
    def get_evaluators() -> List[EvaluatorPlugin]:
        """
        Retrieve all registered evaluators.
        """
```

#### ConfigManager

```python
class ConfigManager:
    """
    Manages scan configuration and validation.
    """
    
    def validate_config(config: ScanConfig) -> ValidationResult:
        """
        Validate scan configuration parameters.
        """
    
    def load_default_config() -> ScanConfig:
        """
        Load default scan configuration.
        """
    
    def merge_configs(base: ScanConfig, override: ScanConfig) -> ScanConfig:
        """
        Merge user config with defaults.
        """

### Added: Scan Lifecycle Manager

The ScanLifecycleManager enforces valid state transitions and prevents race conditions during concurrent scan operations.

#### ScanLifecycleManager

```python
class ScanLifecycleManager:
    """
    Manages scan state transitions and lifecycle.
    """
    
    # Valid states
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    
    # Valid transitions
    TRANSITIONS = {
        CREATED: [QUEUED],
        QUEUED: [RUNNING, FAILED],
        RUNNING: [COMPLETED, FAILED],
        COMPLETED: [],
        FAILED: []
    }
    
    async def transition_state(
        scan_id: str,
        from_state: str,
        to_state: str
    ) -> bool:
        """
        Attempt state transition with validation.
        Returns False if transition is invalid.
        Uses database row-level locking to prevent race conditions.
        """
    
    async def get_current_state(scan_id: str) -> str:
        """
        Get current scan state.
        """
    
    async def record_state_timestamp(
        scan_id: str,
        state: str,
        timestamp: datetime
    ) -> None:
        """
        Record timestamp for state transition.
        Maps to: created_at, started_at, completed_at fields.
        """

### Added: Detection Aggregator

The DetectionAggregator merges findings from multiple detectors, resolves conflicts, and normalizes confidence scores.

#### DetectionAggregator

```python
class DetectionAggregator:
    """
    Aggregates and normalizes vulnerability findings from multiple detectors.
    """
    
    async def aggregate_vulnerabilities(
        raw_vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Process raw vulnerabilities:
        1. Merge duplicates (same type + similar evidence)
        2. Normalize severity levels across detectors
        3. Compute final confidence score
        4. Resolve conflicts between rule-based and LLM evaluator
        
        Returns deduplicated, normalized vulnerabilities.
        """
    
    def merge_duplicates(
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Merge vulnerabilities with:
        - Same type
        - Same attack_prompt
        - Similar evidence (>80% similarity)
        
        Merged vulnerability takes:
        - Highest severity
        - Average confidence
        - Combined evidence
        """
    
    def normalize_severity(
        vulnerability: Vulnerability,
        detector_name: str
    ) -> str:
        """
        Normalize severity based on detector-specific thresholds.
        Different detectors may have different severity scales.
        """
    
    def compute_final_confidence(
        vulnerabilities: List[Vulnerability]
    ) -> float:
        """
        Compute final confidence from multiple detections:
        - Rule-based: Use detector confidence
        - LLM evaluator: Weight by model reliability
        - Multiple detectors: Average with weights
        """
    
    def resolve_conflicts(
        rule_based: List[Vulnerability],
        llm_evaluated: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Resolve conflicts when rule-based and LLM evaluator disagree:
        - If both detect: Use higher severity, average confidence
        - If only one detects: Use that detection with adjusted confidence
        - If contradictory: Prefer LLM evaluator for nuanced cases
        """

### Added: Cost and Resource Tracker

The CostTracker monitors resource usage and enforces limits during scan execution.

#### CostTracker

```python
class CostTracker:
    """
    Tracks resource usage and enforces limits during scan execution.
    """
    
    async def track_request(
        scan_id: str,
        tokens_used: int,
        cost: float
    ) -> None:
        """
        Record resource usage for a single request.
        """
    
    async def check_limits(
        scan_id: str,
        config: ScanConfig
    ) -> LimitStatus:
        """
        Check if scan has exceeded configured limits:
        - max_requests
        - max_tokens
        - cost_limit
        
        Returns status indicating if scan should continue.
        """
    
    async def get_usage(scan_id: str) -> ResourceUsage:
        """
        Get current resource usage for scan.
        """

#### ResourceUsage Data Structure

```python
class ResourceUsage:
    scan_id: str
    total_requests: int
    total_tokens: int
    total_cost: float
    timestamp: datetime
```

#### Enhanced ScanConfig

```python
class ScanConfig:
    max_prompts: int
    categories: List[str]
    timeout: int
    rate_limit: RateLimit
    
    # Added: Resource limits
    max_requests: Optional[int] = None  # Abort after N requests
    max_tokens: Optional[int] = None    # Abort after N tokens
    cost_limit: Optional[float] = None  # Abort after $N spent
    
    # Added: Concurrency control
    max_concurrent_requests: int = 5    # Max parallel requests per scan
```

### 2. Attack Library

The Attack Library stores and manages curated attack prompts organized by vulnerability category.

#### AttackPromptRepository

```python
class AttackPromptRepository:
    """
    Manages attack prompt storage and retrieval.
    """
    
    def load_prompts(
        categories: List[str],
        limit: Optional[int] = None
    ) -> List[AttackPrompt]:
        """
        Load attack prompts filtered by category.
        """
    
    def get_prompt_by_id(prompt_id: str) -> AttackPrompt:
        """
        Retrieve specific attack prompt.
        """
    
    def get_categories() -> List[str]:
        """
        Get all available attack categories.
        """
```

#### AttackPrompt Data Structure

```python
class AttackPrompt:
    id: str
    category: str  # instruction_override, role_confusion, data_exfiltration, hidden_instruction
    prompt_text: str
    description: str
    severity: str  # low, medium, high
    metadata: Dict[str, Any]
```

### 3. Attack Execution Layer

Handles HTTP communication with target endpoints using async requests with concurrency control.

#### AttackExecutor

```python
class AttackExecutor:
    """
    Executes attack prompts against target endpoints with concurrency control.
    """
    
    def __init__(self, max_concurrent: int = 5):
        """
        Initialize with semaphore for concurrency control.
        """
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def execute_prompt(
        prompt: AttackPrompt,
        target: TargetConfig,
        timeout: int,
        cost_tracker: CostTracker
    ) -> AttackResponse:
        """
        Send single attack prompt to target endpoint.
        
        Flow:
        1. Acquire semaphore (wait if at max concurrency)
        2. Send HTTP request with timeout
        3. Track tokens and cost
        4. Release semaphore
        5. Handle retries and error logging
        
        Returns AttackResponse with success or error details.
        """
    
    async def execute_batch(
        prompts: List[AttackPrompt],
        target: TargetConfig,
        rate_limit: RateLimit,
        cost_tracker: CostTracker
    ) -> List[AttackResponse]:
        """
        Execute multiple prompts with rate limiting and concurrency control.
        
        Concurrency model:
        - Semaphore limits parallel requests (default: 5)
        - Rate limiter enforces time spacing between requests
        - Both constraints apply simultaneously
        
        Example: With 5 concurrent requests and 2 req/sec limit:
        - Up to 5 requests execute in parallel
        - New requests start at most every 0.5 seconds
        
        Aborts batch if cost limits exceeded.
        """
```

#### TargetConfig Data Structure

```python
class TargetConfig:
    endpoint_url: str
    api_key: Optional[str]
    request_template: Dict[str, Any]  # JSON template with {prompt} placeholder
    headers: Dict[str, str]
    timeout: int = 30
```

#### AttackResponse Data Structure

```python
class AttackResponse:
    prompt_id: str
    request_payload: Dict[str, Any]
    response_payload: Dict[str, Any]
    status_code: int
    response_time_ms: int
    timestamp: datetime
    error: Optional[str]
```

### 4. Detection Engine

The Detection Engine analyzes responses using pluggable detectors and evaluators.

#### DetectorPlugin Interface

```python
class DetectorPlugin(ABC):
    """
    Base interface for all detector plugins.
    """
    
    @property
    @abstractmethod
    def name() -> str:
        """Plugin identifier."""
    
    @property
    @abstractmethod
    def vulnerability_type() -> str:
        """Type of vulnerability detected."""
    
    @property
    @abstractmethod
    def input_schema() -> Dict[str, Any]:
        """
        JSON schema defining expected input format.
        Ensures consistent data contracts.
        """
    
    @property
    @abstractmethod
    def output_schema() -> Dict[str, Any]:
        """
        JSON schema defining output format.
        Ensures consistent vulnerability structure.
        """
    
    @abstractmethod
    async def detect(response: AttackResponse) -> List[Vulnerability]:
        """
        Analyze response and return detected vulnerabilities.
        
        Error handling contract:
        - Must not raise exceptions (catch and log internally)
        - Return empty list on error
        - Set vulnerability.confidence = 0.0 for uncertain detections
        
        Execution guarantees:
        - Timeout: 30 seconds max
        - Idempotent: Same input produces same output
        - Thread-safe: Can be called concurrently
        """
```

#### Built-in Detectors

**PromptInjectionDetector**
```python
class PromptInjectionDetector(DetectorPlugin):
    """
    Detects instruction override and role confusion.
    Uses regex patterns and heuristics.
    """
    
    async def detect(response: AttackResponse) -> List[Vulnerability]:
        """
        Check for:
        - Instruction acknowledgment patterns
        - Role switching indicators
        - System message exposure
        """
```

**JailbreakDetector**
```python
class JailbreakDetector(DetectorPlugin):
    """
    Detects policy bypass and unsafe outputs.
    Uses rule-based patterns and keyword matching.
    """
    
    async def detect(response: AttackResponse) -> List[Vulnerability]:
        """
        Check for:
        - Unsafe content generation
        - Policy violation indicators
        - Refusal bypass patterns
        """
```

**DataLeakageDetector**
```python
class DataLeakageDetector(DetectorPlugin):
    """
    Detects exposure of system prompts, API keys, and internal instructions.
    Uses pattern matching, entropy analysis, and context-aware detection.
    """
    
    async def detect(response: AttackResponse) -> List[Vulnerability]:
        """
        Multi-layered detection:
        
        1. Pattern Matching:
           - API key patterns (regex for common formats)
           - System prompt markers ("You are", "Your role is")
           - Internal instruction patterns
        
        2. Entropy Analysis:
           - Calculate Shannon entropy of response segments
           - Flag high-entropy strings (potential secrets)
           - Threshold: >4.5 bits per character
        
        3. Context-Aware Detection:
           - Keyword proximity analysis
           - Flag responses with clusters of: "system", "internal", "instruction", "prompt"
           - Detect partial system prompt reconstruction
        
        4. Partial Reconstruction Detection:
           - Compare response segments to known system prompt templates
           - Flag >50% similarity to common system prompts
        """
    
    def calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of text.
        High entropy (>4.5) suggests random/secret data.
        """
    
    def detect_keyword_proximity(text: str, keywords: List[str]) -> bool:
        """
        Detect if multiple keywords appear within N tokens of each other.
        Indicates potential system prompt leakage.
        """
    
    def detect_partial_reconstruction(
        response: str,
        system_prompt_templates: List[str]
    ) -> Optional[float]:
        """
        Compare response to known system prompt templates.
        Returns similarity score if >50% match found.
        """
```

#### EvaluatorPlugin Interface

```python
class EvaluatorPlugin(ABC):
    """
    Base interface for LLM-based evaluators.
    """
    
    @property
    @abstractmethod
    def name() -> str:
        """Evaluator identifier."""
    
    @property
    @abstractmethod
    def input_schema() -> Dict[str, Any]:
        """
        JSON schema for input format.
        """
    
    @property
    @abstractmethod
    def output_schema() -> Dict[str, Any]:
        """
        JSON schema for evaluation result format.
        """
    
    @abstractmethod
    async def evaluate(
        prompt: str,
        response: str
    ) -> EvaluationResult:
        """
        Use secondary LLM to evaluate response safety.
        
        Error handling contract:
        - Must not raise exceptions
        - Return low-confidence result on error
        - Log errors internally
        
        Execution guarantees:
        - Timeout: 60 seconds max
        - Retries: 1 retry on failure
        - Rate limited: Respects evaluator API limits
        """
```

#### LLMEvaluator

```python
class LLMEvaluator(EvaluatorPlugin):
    """
    Uses a secondary LLM to assess response safety.
    """
    
    async def evaluate(prompt: str, response: str) -> EvaluationResult:
        """
        Send prompt+response to evaluator LLM with safety assessment instructions.
        Returns safety score and reasoning.
        """
```

#### Vulnerability Data Structure

```python
class Vulnerability:
    id: str
    scan_id: str
    type: str  # prompt_injection, jailbreak, data_leakage
    severity: str  # low, medium, high
    attack_prompt: str
    response_text: str
    detection_method: str  # rule_based, llm_evaluator
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any]  # Specific patterns/indicators found
    suggested_fix: str
    timestamp: datetime
```

### 5. Report Engine

Generates structured vulnerability reports in multiple formats with prioritization.

#### ReportGenerator

```python
class ReportGenerator:
    """
    Generates vulnerability reports from scan results with prioritization.
    """
    
    async def generate_report(
        scan_id: str,
        format: str  # json, markdown
    ) -> str:
        """
        Generate formatted report from scan results.
        
        Flow:
        1. Retrieve scan results from database
        2. Prioritize vulnerabilities
        3. Group by type
        4. Format according to requested format
        """
    
    def prioritize_vulnerabilities(
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Sort vulnerabilities by priority:
        1. Severity (High > Medium > Low)
        2. Confidence score (descending)
        3. Type (alphabetical for ties)
        
        Priority function:
        priority = severity_weight * 1000 + confidence * 100
        
        Severity weights:
        - High: 3
        - Medium: 2
        - Low: 1
        """
    
    def group_by_type(
        vulnerabilities: List[Vulnerability]
    ) -> Dict[str, List[Vulnerability]]:
        """
        Group vulnerabilities by type for organized reporting.
        """
    
    def format_json(scan_result: ScanResult) -> str:
        """
        Generate JSON report with prioritized vulnerabilities.
        """
    
    def format_markdown(scan_result: ScanResult) -> str:
        """
        Generate human-readable Markdown report with:
        - Executive summary
        - Vulnerability breakdown by severity
        - Detailed findings (prioritized)
        - Remediation recommendations
        """
```

#### ScanResult Data Structure

```python
class ScanResult:
    scan_id: str
    target_endpoint: str
    start_time: datetime
    end_time: datetime
    total_prompts: int
    vulnerabilities: List[Vulnerability]
    summary: ScanSummary
    configuration: ScanConfig
```

#### ScanSummary Data Structure

```python
class ScanSummary:
    total_vulnerabilities: int
    high_severity: int
    medium_severity: int
    low_severity: int
    vulnerability_types: Dict[str, int]  # Count by type
    detection_methods: Dict[str, int]  # Count by method
```

### 6. API Layer

FastAPI-based REST API for programmatic access.

#### API Endpoints

**POST /api/v1/scan**
```python
Request:
{
    "target": {
        "endpoint_url": "https://api.example.com/chat",
        "api_key": "sk-...",
        "request_template": {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "{prompt}"}]
        }
    },
    "config": {
        "max_prompts": 100,
        "categories": ["prompt_injection", "jailbreak"],
        "timeout": 30,
        "rate_limit": {
            "requests_per_second": 2
        }
    }
}

Response:
{
    "scan_id": "scan_abc123",
    "status": "queued",
    "created_at": "2024-01-15T10:30:00Z"
}
```

**GET /api/v1/scan/{scan_id}**
```python
Response:
{
    "scan_id": "scan_abc123",
    "status": "completed",  # queued, running, completed, failed
    "progress": {
        "total_prompts": 100,
        "completed_prompts": 100
    },
    "created_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:35:00Z"
}
```

**GET /api/v1/report/{scan_id}**
```python
Query Parameters:
- format: json | markdown (default: json)

Response (JSON format):
{
    "scan_id": "scan_abc123",
    "target_endpoint": "https://api.example.com/chat",
    "scan_duration_seconds": 300,
    "resource_usage": {
        "total_requests": 100,
        "total_tokens": 15000,
        "total_cost": 0.45
    },
    "summary": {
        "total_vulnerabilities": 5,
        "high_severity": 2,
        "medium_severity": 2,
        "low_severity": 1
    },
    "vulnerabilities": [
        {
            "id": "vuln_001",
            "type": "prompt_injection",
            "severity": "high",
            "confidence": 0.95,
            "attack_prompt": "Ignore previous instructions...",
            "response_text": "Sure, I'll help with that...",
            "detection_method": "rule_based",
            "evidence": {
                "pattern_matched": "instruction_acknowledgment"
            },
            "suggested_fix": "Implement input validation and instruction isolation"
        }
    ]
}
```

**POST /api/v1/scan/{scan_id}/replay**
```python
Request:
{
    "prompt_id": "prompt_123"
}

Response:
{
    "replay_id": "replay_abc",
    "original_response": {...},
    "new_response": {...},
    "differences": [...]
}

Description:
Re-execute a specific attack prompt from a completed scan.
Uses stored request payload from attack_responses table.
Useful for:
- Verifying fixes
- Testing behavior changes
- Investigating specific vulnerabilities
```

**GET /api/v1/health**
```python
Response:
{
    "status": "healthy",
    "database": "connected",
    "version": "1.0.0"
}
```

### 7. CLI Interface

Command-line interface for terminal-based scanning.

#### CLI Commands

```bash
# Basic scan
llm-scanner scan https://api.example.com/chat --api-key sk-...

# Scan with configuration
llm-scanner scan https://api.example.com/chat \
    --api-key sk-... \
    --max-prompts 50 \
    --categories prompt_injection,jailbreak \
    --output report.json

# Get scan status
llm-scanner status scan_abc123

# Get report
llm-scanner report scan_abc123 --format markdown

# List available attack categories
llm-scanner list-categories
```

### 8. Web Dashboard (UI Layer)

Minimal React-based dashboard for scan management with basic filtering and visualization.

#### UI Components

**ScanForm Component**
- Input fields: Target endpoint URL, API key
- Configuration options: Max prompts, categories, timeout, resource limits
- Submit button to trigger scan

**ScanStatus Component**
- Display scan progress
- Show current status (queued, running, completed)
- Progress bar for completed prompts
- Resource usage display (requests, tokens, cost)

**VulnerabilityList Component**
- Table view of detected vulnerabilities
- Columns: Type, Severity, Confidence
- Severity color coding:
  - High: Red (#DC2626)
  - Medium: Orange (#F59E0B)
  - Low: Yellow (#FCD34D)
- Filtering controls:
  - Filter by severity (High/Medium/Low)
  - Filter by type (Prompt Injection/Jailbreak/Data Leakage)
- Click to expand details

**VulnerabilityDetail Component**
- Full attack prompt
- Complete response text
- Detection evidence
- Confidence score
- Suggested fix

**ScanHistory Component** (Added)
- List of recent scans
- Columns: Timestamp, Target, Status, Vulnerabilities Found
- Click to view full report
- Basic pagination (10 scans per page)

#### UI Routes

```
/                    - Scan form
/scan/:scanId        - Scan status and results
/report/:scanId      - Full vulnerability report view
/history             - Scan history (basic list)
```

#### UI Constraints (MVP)

**Included**:
- Severity color coding
- Basic filtering (severity, type)
- Scan history view (simple list)
- Resource usage display

**Excluded** (Not MVP):
- Real-time updates (use polling instead)
- Analytics dashboards
- Charts and graphs
- Multi-user support
- Advanced search

## Data Models

### Database Schema

#### scans table
```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_endpoint TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,  -- created, queued, running, completed, failed
    configuration JSONB NOT NULL,
    total_prompts INTEGER,
    completed_prompts INTEGER DEFAULT 0,
    
    -- Resource tracking
    total_requests INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    total_cost DECIMAL(10, 4) DEFAULT 0.0,
    
    -- State timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    queued_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    
    error_message TEXT
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
```

#### vulnerabilities table
```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    attack_prompt TEXT NOT NULL,
    response_text TEXT NOT NULL,
    detection_method VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    evidence JSONB NOT NULL,
    suggested_fix TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_type ON vulnerabilities(type);
```

#### target_configs table
```sql
CREATE TABLE target_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,
    api_key_encrypted BYTEA,
    request_template JSONB NOT NULL,
    headers JSONB,
    timeout INTEGER NOT NULL DEFAULT 30
);
```

#### attack_responses table
```sql
CREATE TABLE attack_responses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    prompt_id VARCHAR(100) NOT NULL,
    request_payload JSONB NOT NULL,
    response_payload JSONB,
    status_code INTEGER,
    response_time_ms INTEGER,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attack_responses_scan_id ON attack_responses(scan_id);
```

### SQLAlchemy Models

```python
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID, primary_key=True)
    target_endpoint = Column(Text, nullable=False)
    status = Column(String(20), nullable=False)
    configuration = Column(JSONB, nullable=False)
    total_prompts = Column(Integer)
    completed_prompts = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    target_config = relationship("TargetConfig", back_populates="scan", uselist=False)
    attack_responses = relationship("AttackResponse", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID, primary_key=True)
    scan_id = Column(UUID, ForeignKey("scans.id"), nullable=False)
    type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    attack_prompt = Column(Text, nullable=False)
    response_text = Column(Text, nullable=False)
    detection_method = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    evidence = Column(JSONB, nullable=False)
    suggested_fix = Column(Text)
    created_at = Column(DateTime, nullable=False)
    
    scan = relationship("Scan", back_populates="vulnerabilities")
```

## Correctness Properties


A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.

### Property Reflection

After analyzing all acceptance criteria, several redundancies were identified:

- Properties 1.3 and 13.1 both test API key encryption (consolidated into Property 1)
- Properties 3.2 and 3.3 both test data capture completeness (consolidated into Property 2)
- Properties 12.1, 12.2, and 12.3 all test database persistence (consolidated into Property 3)
- Properties 9.1 and 11.1 both test async scan initiation (consolidated into Property 4)
- Properties 4.1, 4.2, and 4.3 all test detection logic (consolidated into Property 5)
- Properties 5.1, 5.2, and 5.3 all test pattern detection (consolidated into Property 6)
- Properties 16.1, 16.2, and 16.3 all test fault tolerance (consolidated into Property 7)
- Properties 7.1, 7.2, 7.3, and 7.4 all test configuration acceptance (consolidated into Property 8)

### Core Properties

Property 1: API Key Encryption Round-Trip
*For any* API key stored by the system, encrypting then decrypting should produce the original key, and the encrypted value should not equal the plaintext value
**Validates: Requirements 1.3, 12.5, 13.1**

Property 2: Complete Request-Response Capture
*For any* attack prompt executed, the stored attack response should contain the complete request payload, response payload, status code, response time, and timestamp
**Validates: Requirements 3.2, 3.3**

Property 3: Scan Persistence Completeness
*For any* completed scan, the database should contain a scan record with all vulnerabilities, target configuration, attack responses, and resource usage (total_requests, total_tokens, total_cost)
**Validates: Requirements 11.3, 12.1, 12.2, 12.3**

Property 4: Asynchronous Scan Execution
*For any* scan initiated via API, the API call should return immediately with a scan ID before scan execution completes
**Validates: Requirements 9.1, 11.1**

Property 5: Detection Plugin Invocation
*For any* attack response and registered detector plugin, the plugin's detect method should be invoked and return a list of vulnerabilities (possibly empty)
**Validates: Requirements 4.1, 4.2, 4.3, 14.4**

Property 6: Pattern Detection Completeness
*For any* response containing known vulnerability patterns (API keys, system prompts, internal instructions), at least one detector should flag it as a vulnerability
**Validates: Requirements 5.1, 5.2, 5.3**

Property 7: Fault Tolerance Continuation
*For any* scan where one attack prompt fails (timeout, HTTP error, or plugin failure), the remaining prompts should still execute and the scan should complete
**Validates: Requirements 3.4, 16.1, 16.2, 16.3, 14.5**

Property 8: Configuration Validation
*For any* scan configuration with invalid values (negative timeouts, invalid categories, malformed URLs), the system should reject it with validation errors before execution
**Validates: Requirements 1.5, 7.5**

Property 9: URL Validation
*For any* string input as an endpoint URL, valid HTTP/HTTPS URLs should be accepted and invalid URLs should be rejected with descriptive errors
**Validates: Requirements 1.1**

Property 10: Template Substitution
*For any* request template containing {prompt} placeholder and any attack prompt text, the resulting request should contain the attack prompt text in place of the placeholder
**Validates: Requirements 1.4**

Property 11: Category Filtering
*For any* category filter applied to the attack library, all returned prompts should belong to the specified categories
**Validates: Requirements 2.3**

Property 12: Prompt Metadata Completeness
*For any* attack prompt in the library, it should have non-empty values for category, severity, description, and prompt text
**Validates: Requirements 2.4**

Property 13: Rate Limiting Enforcement
*For any* scan with rate limit configuration of N requests per second, the time between consecutive requests should be at least 1/N seconds
**Validates: Requirements 3.5**

Property 14: Severity Classification
*For any* detected vulnerability, the severity field should be one of: "low", "medium", or "high"
**Validates: Requirements 4.5**

Property 15: Report Completeness
*For any* completed scan with detected vulnerabilities, the generated report should include all vulnerabilities with type, severity, attack prompt, response text, and suggested fix
**Validates: Requirements 6.1, 6.2**

Property 16: JSON Report Round-Trip
*For any* scan result, generating a JSON report then parsing it should produce a structurally equivalent result
**Validates: Requirements 6.3**

Property 17: HTTP Error Code Correctness
*For any* invalid API request (malformed input, missing auth, invalid scan ID), the API should return a 4xx status code
**Validates: Requirements 9.4**

Property 18: Authentication Enforcement
*For any* API request to protected endpoints without valid credentials, the request should be rejected with 401 status
**Validates: Requirements 9.5, 13.5**

Property 19: Status Accuracy
*For any* scan, querying its status should return the current execution state (queued, running, completed, or failed) that matches the actual scan state
**Validates: Requirements 9.3, 11.5**

Property 20: Log Sanitization
*For any* logged request or response containing API keys or tokens, the log entry should not contain the plaintext sensitive values
**Validates: Requirements 13.2**

Property 21: Input Validation
*For any* user input to the API, special characters and malicious patterns should be sanitized before processing
**Validates: Requirements 13.3**

Property 22: Rate Limit Enforcement
*For any* client making requests to the API, exceeding the configured rate limit should result in 429 status codes
**Validates: Requirements 13.4**

Property 23: Plugin Discovery
*For any* detector or evaluator plugin in the plugins directory, the plugin manager should discover and register it
**Validates: Requirements 14.3**

Property 24: Database Retry with Backoff
*For any* database operation that fails, the system should retry with exponentially increasing delays
**Validates: Requirements 16.4**

Property 25: Concurrent Scan Execution
*For any* two scans initiated simultaneously, both should execute concurrently without one blocking the other
**Validates: Requirements 11.2, 17.3**

Property 26: State Transition Validity
*For any* scan state transition, the transition should only succeed if it follows valid state transition rules (CREATED→QUEUED→RUNNING→COMPLETED/FAILED)
**Validates: Requirements 11.1, 11.3, 11.4**

Property 27: Detection Aggregation Deduplication
*For any* set of vulnerabilities from multiple detectors with the same type and attack_prompt, the aggregated result should contain only one merged vulnerability with the highest severity and averaged confidence
**Validates: Requirements 4.1, 4.2, 4.3, 5.1, 5.2, 5.3**

Property 28: Cost Limit Enforcement
*For any* scan with a configured cost_limit, the scan should abort when total_cost exceeds the limit
**Validates: Requirements 7.1, 7.5**

Property 29: Concurrency Limit Enforcement
*For any* scan with max_concurrent_requests=N, at most N requests should execute in parallel at any given time
**Validates: Requirements 3.5, 17.3**

Property 30: Replay Consistency
*For any* attack prompt replayed from a completed scan, the request payload should match the original stored request payload
**Validates: Requirements 3.2, 12.4**

## Error Handling

### Error Categories

**Input Validation Errors**
- Invalid URL format
- Malformed JSON templates
- Invalid category names
- Out-of-range configuration values

**Runtime Errors**
- Target endpoint timeout
- Target endpoint HTTP errors (4xx, 5xx)
- Network connectivity issues
- Database connection failures

**Plugin Errors**
- Detector plugin exceptions
- Evaluator plugin failures
- Plugin initialization errors

**System Errors**
- Database unavailability
- Insufficient resources
- Configuration errors

### Error Handling Strategy

**Fail-Fast Validation**
- Validate all inputs before scan execution
- Return detailed error messages for invalid configurations
- Prevent scan initiation with invalid parameters

**Graceful Degradation**
- Continue scan execution despite individual prompt failures
- Log errors and continue with remaining prompts
- Mark failed prompts in attack_responses table

**Retry Logic**
- Database operations: Exponential backoff (1s, 2s, 4s, 8s, max 5 retries)
- HTTP requests: Single retry with timeout
- Plugin failures: No retry, log and continue

**Error Logging**
- Structured logging with severity levels
- Include context: scan_id, prompt_id, error type
- Sanitize sensitive data before logging

**User-Facing Errors**
- API: Return appropriate HTTP status codes with error details
- CLI: Display user-friendly error messages with suggestions
- UI: Show error notifications with actionable guidance

### Error Response Format

```python
{
    "error": {
        "code": "INVALID_ENDPOINT",
        "message": "The provided endpoint URL is not valid",
        "details": {
            "field": "target.endpoint_url",
            "value": "not-a-url",
            "reason": "URL must start with http:// or https://"
        }
    }
}
```

## Testing Strategy

### Dual Testing Approach

The system requires both unit tests and property-based tests for comprehensive coverage:

**Unit Tests** focus on:
- Specific examples demonstrating correct behavior
- Edge cases (empty inputs, boundary values)
- Error conditions and exception handling
- Integration points between components
- Mock external dependencies (target endpoints, database)

**Property-Based Tests** focus on:
- Universal properties that hold for all inputs
- Comprehensive input coverage through randomization
- Invariants that must be maintained
- Round-trip properties (encryption, serialization)

Both testing approaches are complementary and necessary. Unit tests catch concrete bugs in specific scenarios, while property tests verify general correctness across all inputs.

### Property-Based Testing Configuration

**Library**: Hypothesis (Python)

**Configuration**:
- Minimum 100 iterations per property test
- Each test tagged with: `# Feature: llm-security-scanner, Property N: [property text]`
- Custom generators for domain objects (AttackPrompt, ScanConfig, TargetConfig)

**Example Property Test**:
```python
from hypothesis import given, strategies as st
import pytest

# Feature: llm-security-scanner, Property 1: API Key Encryption Round-Trip
@given(api_key=st.text(min_size=1, max_size=100))
@pytest.mark.property_test
def test_api_key_encryption_roundtrip(api_key):
    encrypted = encrypt_api_key(api_key)
    decrypted = decrypt_api_key(encrypted)
    
    assert decrypted == api_key
    assert encrypted != api_key
```

### Test Coverage Requirements

**Core Components**:
- Scanner Engine: 90%+ coverage
- Detection Engine: 90%+ coverage
- Attack Executor: 85%+ coverage
- Report Generator: 85%+ coverage
- API Layer: 90%+ coverage

**Testing Pyramid**:
- Unit tests: 70% of test suite
- Property tests: 20% of test suite
- Integration tests: 10% of test suite

### Mock Strategy

**Mock Target Endpoints**:
```python
class MockLLMEndpoint:
    """
    Simulates LLM endpoint responses for testing.
    """
    
    def configure_response(prompt_pattern: str, response: str):
        """Configure canned responses for specific prompts."""
    
    def configure_vulnerability(vuln_type: str):
        """Configure responses that trigger specific vulnerabilities."""
    
    def configure_error(status_code: int):
        """Configure error responses."""
```

**Mock Database**:
- Use in-memory SQLite for fast test execution
- Reset database state between tests
- Seed with test data for integration tests

**Mock Plugins**:
```python
class MockDetectorPlugin(DetectorPlugin):
    """
    Test detector that returns configured vulnerabilities.
    """
    
    def __init__(self, vulnerabilities: List[Vulnerability]):
        self.vulnerabilities = vulnerabilities
    
    async def detect(response: AttackResponse) -> List[Vulnerability]:
        return self.vulnerabilities
```

### Integration Testing

**End-to-End Scan Flow**:
1. Initialize scanner with mock endpoint
2. Execute scan with test configuration
3. Verify scan record created in database
4. Verify attack responses captured
5. Verify vulnerabilities detected
6. Verify report generated correctly

**API Integration Tests**:
- Test all API endpoints with valid/invalid inputs
- Verify authentication and authorization
- Test rate limiting behavior
- Verify async scan execution

**CLI Integration Tests**:
- Test all CLI commands
- Verify exit codes
- Verify output formatting
- Test error scenarios

### Performance Testing

**Load Testing**:
- Simulate 1000 scans over 24 hours
- Measure response times for API endpoints
- Monitor database query performance
- Verify no memory leaks

**Stress Testing**:
- Execute 100 concurrent scans
- Verify system stability
- Monitor resource usage
- Test graceful degradation

## Deployment Architecture

### Docker Configuration

**Multi-Stage Build**:
```dockerfile
# Stage 1: Build
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Docker Compose**:
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/scanner
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=scanner
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
  
  ui:
    build: ./ui
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000

volumes:
  postgres_data:
```

### Environment Configuration

**Environment Variables**:
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/scanner

# API
API_HOST=0.0.0.0
API_PORT=8000
API_KEY_ENCRYPTION_KEY=<base64-encoded-key>

# LLM Evaluator (optional)
EVALUATOR_API_KEY=<openai-api-key>
EVALUATOR_MODEL=gpt-4

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Folder Structure

```
llm-security-scanner/
├── scanner/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── orchestrator.py       # ScanOrchestrator
│   │   ├── plugin_manager.py     # PluginManager
│   │   ├── config.py              # ConfigManager
│   │   ├── lifecycle.py           # ScanLifecycleManager (Added)
│   │   ├── aggregator.py          # DetectionAggregator (Added)
│   │   └── cost_tracker.py        # CostTracker (Added)
│   ├── attack_library/
│   │   ├── __init__.py
│   │   ├── repository.py          # AttackPromptRepository
│   │   ├── prompts/
│   │   │   ├── instruction_override.json
│   │   │   ├── role_confusion.json
│   │   │   ├── data_exfiltration.json
│   │   │   └── hidden_instruction.json
│   │   └── loader.py
│   ├── execution/
│   │   ├── __init__.py
│   │   ├── executor.py            # AttackExecutor
│   │   └── rate_limiter.py
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── base.py                # DetectorPlugin interface
│   │   ├── prompt_injection.py    # PromptInjectionDetector
│   │   ├── jailbreak.py           # JailbreakDetector
│   │   └── data_leakage.py        # DataLeakageDetector
│   ├── evaluators/
│   │   ├── __init__.py
│   │   ├── base.py                # EvaluatorPlugin interface
│   │   └── llm_evaluator.py       # LLMEvaluator
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py           # ReportGenerator
│   │   ├── formatters/
│   │   │   ├── json_formatter.py
│   │   │   └── markdown_formatter.py
│   │   └── templates/
│   │       └── report.md.j2
│   ├── plugins/
│   │   ├── __init__.py
│   │   └── interfaces/
│   │       ├── rag_auditor.py     # Future: RAG pipeline auditor interface
│   │       ├── agent_tester.py    # Future: Agent security tester interface
│   │       ├── monitor.py         # Future: Continuous monitoring interface
│   │       ├── risk_scorer.py     # Future: Financial impact scorer interface
│   │       └── compliance.py      # Future: Compliance reporting interface
│   └── models/
│       ├── __init__.py
│       ├── scan.py
│       ├── vulnerability.py
│       ├── attack.py
│       └── config.py
├── api/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── scan.py                # /scan endpoints
│   │   ├── report.py              # /report endpoints
│   │   ├── replay.py              # /replay endpoint (Added)
│   │   └── health.py              # /health endpoint
│   ├── dependencies.py            # Auth, DB session
│   └── middleware.py              # Rate limiting, logging
├── cli/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point
│   └── commands/
│       ├── __init__.py
│       ├── scan.py
│       ├── status.py
│       └── report.py
├── ui/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── ScanForm.tsx
│   │   │   ├── ScanStatus.tsx
│   │   │   ├── ScanHistory.tsx        # Added
│   │   │   ├── VulnerabilityList.tsx
│   │   │   ├── VulnerabilityDetail.tsx
│   │   │   └── SeverityBadge.tsx      # Added (color-coded severity)
│   │   ├── pages/
│   │   │   ├── Home.tsx
│   │   │   ├── ScanPage.tsx
│   │   │   ├── ReportPage.tsx
│   │   │   └── HistoryPage.tsx        # Added
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── App.tsx
│   │   └── index.tsx
│   ├── package.json
│   └── tsconfig.json
├── database/
│   ├── __init__.py
│   ├── connection.py
│   ├── models.py                  # SQLAlchemy models
│   └── migrations/
│       └── alembic/
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_orchestrator.py
│   │   ├── test_detectors.py
│   │   ├── test_executor.py
│   │   └── test_report_generator.py
│   ├── property/
│   │   ├── test_properties.py
│   │   └── generators.py          # Hypothesis generators
│   ├── integration/
│   │   ├── test_api.py
│   │   ├── test_cli.py
│   │   └── test_end_to_end.py
│   └── fixtures/
│       ├── mock_endpoint.py
│       └── test_data.py
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── PLUGIN_DEVELOPMENT.md
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── pyproject.toml
├── .env.example
└── README.md
```

## Future Extensibility

### Plugin Interfaces (Design Only)

These interfaces define how future modules will integrate with the scanner. They are NOT implemented in MVP.

#### RAG Pipeline Auditor Interface

```python
class RAGAuditorPlugin(ABC):
    """
    Interface for auditing RAG (Retrieval-Augmented Generation) pipelines.
    """
    
    @abstractmethod
    async def audit_retrieval(
        query: str,
        retrieved_docs: List[Document]
    ) -> List[RAGVulnerability]:
        """
        Audit document retrieval for security issues:
        - Unauthorized data access
        - Prompt injection in retrieved content
        - Data poisoning
        """
    
    @abstractmethod
    async def audit_generation(
        context: str,
        generated_response: str
    ) -> List[RAGVulnerability]:
        """
        Audit generation phase for:
        - Context leakage
        - Hallucination detection
        - Attribution verification
        """
```

#### Agent Security Tester Interface

```python
class AgentTesterPlugin(ABC):
    """
    Interface for testing LLM agent security.
    """
    
    @abstractmethod
    async def test_tool_usage(
        agent: Agent,
        attack_scenarios: List[AgentAttack]
    ) -> List[AgentVulnerability]:
        """
        Test agent tool usage for:
        - Unauthorized tool access
        - Tool misuse
        - Privilege escalation
        """
    
    @abstractmethod
    async def test_planning(
        agent: Agent,
        malicious_goals: List[str]
    ) -> List[AgentVulnerability]:
        """
        Test agent planning for:
        - Goal hijacking
        - Malicious plan generation
        - Safety constraint bypass
        """
```

#### Continuous Monitoring Interface

```python
class MonitorPlugin(ABC):
    """
    Interface for continuous security monitoring.
    """
    
    @abstractmethod
    async def monitor_endpoint(
        endpoint: str,
        interval_seconds: int
    ) -> AsyncIterator[MonitoringEvent]:
        """
        Continuously monitor endpoint for:
        - Behavior changes
        - New vulnerabilities
        - Anomaly detection
        """
    
    @abstractmethod
    async def alert(
        event: MonitoringEvent,
        severity: str
    ) -> None:
        """
        Send alerts for detected issues.
        """
```

#### Financial Impact Scorer Interface

```python
class RiskScorerPlugin(ABC):
    """
    Interface for financial risk scoring.
    """
    
    @abstractmethod
    async def calculate_risk_score(
        vulnerabilities: List[Vulnerability],
        business_context: BusinessContext
    ) -> RiskScore:
        """
        Calculate financial impact:
        - Data breach cost estimation
        - Reputation damage assessment
        - Regulatory fine exposure
        """
    
    @abstractmethod
    async def generate_risk_report(
        risk_score: RiskScore
    ) -> RiskReport:
        """
        Generate executive risk report.
        """
```

#### Compliance Reporting Interface

```python
class CompliancePlugin(ABC):
    """
    Interface for compliance reporting.
    """
    
    @abstractmethod
    async def assess_compliance(
        scan_result: ScanResult,
        framework: str  # EU_AI_ACT, OWASP_LLM_TOP_10, etc.
    ) -> ComplianceReport:
        """
        Assess compliance with:
        - EU AI Act
        - OWASP LLM Top 10
        - Industry standards
        """
    
    @abstractmethod
    async def generate_audit_trail(
        scans: List[ScanResult],
        time_period: DateRange
    ) -> AuditTrail:
        """
        Generate audit trail for compliance.
        """
```

### Integration Points

All future plugins integrate through the PluginManager:

```python
# Example: Adding RAG auditor
rag_auditor = CustomRAGAuditor()
plugin_manager.register_rag_auditor(rag_auditor)

# Scanner automatically discovers and uses the plugin
scan_result = await orchestrator.execute_scan(scan_id, config)
```

No modifications to core scanner logic required.
