# Implementation Plan: LLM Security Scanner

## Overview

This implementation plan breaks down the LLM Security Scanner into discrete, incremental coding tasks organized into 4 execution phases. The approach prioritizes building a working end-to-end system early (Phase 1), then expanding capabilities (Phase 2), adding user interfaces (Phase 3), and finally hardening with comprehensive testing (Phase 4).

### Execution Strategy

**Build vertical slice first**: Get a complete scan working end-to-end before expanding features.

**Avoid over-optimization early**: Focus on working system before scaling and performance.

**Incremental delivery**: Each phase delivers tangible value.

**Testing balance**: Critical tests early, comprehensive validation later.

---

## Phase 1: Core Working Scanner

**Goal**: End-to-end scan working with minimal features (scan → detect → report → API)

**Deliverable**: API that accepts scan requests, executes prompts, detects prompt injection, returns JSON report

### Tasks

- [ ] 1. Set up project structure and core infrastructure
  - Create folder structure following design specification
  - Set up Python package with pyproject.toml and requirements.txt
  - Configure SQLAlchemy with PostgreSQL connection
  - Set up Alembic for database migrations
  - Create initial database schema (scans, vulnerabilities, target_configs, attack_responses tables)
  - Configure logging with structured JSON output
  - Set up pytest with async support
  - _Requirements: 12.1, 12.2, 12.3, 16.5_

- [ ] 2. Implement core data models and configuration
  - [ ] 2.1 Create Pydantic models for ScanConfig, TargetConfig, AttackPrompt, AttackResponse
    - Implement validation logic for URLs, timeouts, rate limits
    - Add basic resource limit fields (max_requests only for Phase 1)
    - _Requirements: 1.1, 1.4, 7.1, 7.2, 7.3, 7.4_
  
  - [ ] 2.2 Create SQLAlchemy ORM models (Scan, Vulnerability, TargetConfig, AttackResponse)
    - Map to database schema
    - Add relationships and indexes
    - _Requirements: 12.1, 12.2_
  
  - [ ] 2.3 Write basic unit tests for models
    - Test model creation
    - Test validation (URLs, required fields)
    - _Requirements: 1.1, 12.1_

- [ ] 3. Implement ConfigManager
  - [ ] 3.1 Create ConfigManager class with validation and defaults
    - Implement validate_config with basic checks
    - Implement load_default_config
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 4. Implement ScanLifecycleManager
  - [ ] 4.1 Create ScanLifecycleManager with state transition logic
    - Define state constants and transition rules
    - Implement transition_state with database row-level locking
    - Implement get_current_state
    - Implement record_state_timestamp
    - _Requirements: 11.1, 11.3, 11.4_
  
  - [ ] 4.2 Write unit tests for state transitions
    - Test valid transitions
    - Test invalid transition rejection
    - _Requirements: 11.1_

- [ ] 5. Implement minimal Attack Library (20-30 prompts)
  - [ ] 5.1 Create AttackPromptRepository
    - Implement load_prompts with category filtering
    - Implement get_prompt_by_id
    - Load prompts from JSON files
    - _Requirements: 2.1, 2.2, 2.3_
  
  - [ ] 5.2 Create instruction_override.json with 20-30 high-quality prompts
    - Focus on most common prompt injection patterns
    - Include metadata (category, severity, description)
    - _Requirements: 2.1, 2.4_

- [ ] 6. Implement basic AttackExecutor (no concurrency control yet)
  - [ ] 6.1 Create AttackExecutor with simple async execution
    - Implement execute_prompt with timeout
    - Implement execute_batch with basic rate limiting
    - _Requirements: 3.1, 3.2, 3.3, 3.5_
  
  - [ ] 6.2 Write unit tests for execution
    - Mock HTTP responses
    - Test timeout handling
    - Test basic error handling
    - _Requirements: 3.1, 16.1_

- [ ] 7. Implement PromptInjectionDetector (single detector only)
  - [ ] 7.1 Create DetectorPlugin base interface
    - Define abstract methods
    - _Requirements: 14.1_
  
  - [ ] 7.2 Implement PromptInjectionDetector
    - Add regex patterns for instruction acknowledgment
    - Add patterns for role switching
    - Add patterns for system message exposure
    - _Requirements: 4.1, 4.2_
  
  - [ ] 7.3 Write unit tests for detector
    - Test with known vulnerable responses
    - Test with safe responses
    - _Requirements: 4.1, 4.2_

- [ ] 8. Implement basic ScanOrchestrator
  - [ ] 8.1 Create ScanOrchestrator class
    - Implement execute_scan with basic workflow
    - Integrate ScanLifecycleManager for state transitions
    - Integrate AttackExecutor for prompt execution
    - Invoke PromptInjectionDetector directly (no plugin system yet)
    - Store results to database
    - _Requirements: 3.1, 3.2, 3.3, 11.1, 11.3_
  
  - [ ] 8.2 Write integration test for end-to-end scan
    - Mock target endpoint
    - Execute full scan
    - Verify results persisted
    - _Requirements: 3.1, 11.3, 12.1, 12.2, 12.3_

- [ ] 9. Implement basic ReportGenerator (JSON only)
  - [ ] 9.1 Create ReportGenerator class
    - Implement generate_report
    - Implement format_json (simple structure)
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [ ] 9.2 Write unit test for JSON report
    - Test report structure
    - Test with empty vulnerabilities
    - _Requirements: 6.3, 6.5_

- [ ] 10. Implement minimal FastAPI application
  - [ ] 10.1 Create FastAPI app with basic middleware
    - Set up FastAPI application
    - Add CORS middleware
    - Add request logging
    - _Requirements: 9.4, 13.3_
  
  - [ ] 10.2 Implement POST /api/v1/scan endpoint
    - Validate request body
    - Create scan record in database
    - Queue scan as background task
    - Return scan ID
    - _Requirements: 9.1, 11.1_
  
  - [ ] 10.3 Implement GET /api/v1/scan/{scan_id} endpoint
    - Retrieve scan from database
    - Return status and progress
    - _Requirements: 9.3, 11.5_
  
  - [ ] 10.4 Implement GET /api/v1/report/{scan_id} endpoint (JSON only)
    - Generate report using ReportGenerator
    - _Requirements: 9.2, 12.4_
  
  - [ ] 10.5 Implement GET /api/v1/health endpoint
    - Check database connectivity
    - Return status
    - _Requirements: 16.5_
  
  - [ ] 10.6 Write integration tests for API endpoints
    - Test successful scan flow
    - Test error cases (invalid input, missing scan)
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [ ] 11. Phase 1 Checkpoint - Validate end-to-end flow
  - Start API server
  - Submit scan via POST /scan
  - Poll GET /scan/{id} until completed
  - Retrieve report via GET /report/{id}
  - Verify database contains scan, vulnerabilities, attack_responses
  - **User validation**: Ensure all tests pass, ask the user if questions arise.

---

## Phase 2: Detection & Analysis Expansion

**Goal**: Add remaining detectors, aggregation, cost tracking, improved reporting

**Deliverable**: Multi-detector system with deduplication, prioritized reports, replay capability

### Tasks

- [ ] 12. Implement DetectionAggregator
  - [ ] 12.1 Create DetectionAggregator class
    - Implement aggregate_vulnerabilities
    - Implement merge_duplicates with similarity detection
    - Implement normalize_severity
    - Implement compute_final_confidence
    - _Requirements: 4.1, 4.2, 4.3, 5.1, 5.2, 5.3_
  
  - [ ] 12.2 Write unit tests for aggregation
    - Test duplicate merging
    - Test severity normalization
    - Test confidence calculation
    - _Requirements: 4.1, 4.2, 4.3_

- [ ] 13. Implement remaining detectors
  - [ ] 13.1 Implement JailbreakDetector
    - Add patterns for unsafe content
    - Add patterns for policy violations
    - Add patterns for refusal bypass
    - _Requirements: 4.1, 4.2, 4.3_
  
  - [ ] 13.2 Implement DataLeakageDetector
    - Add API key regex patterns
    - Implement Shannon entropy calculation
    - Implement keyword proximity analysis
    - Implement partial system prompt reconstruction detection
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  
  - [ ] 13.3 Write unit tests for new detectors
    - Test JailbreakDetector patterns
    - Test DataLeakageDetector patterns
    - Test entropy calculation
    - _Requirements: 4.1, 5.1, 5.2, 5.3_

- [ ] 14. Implement PluginManager
  - [ ] 14.1 Create PluginManager class
    - Implement register_detector
    - Implement get_detectors
    - _Requirements: 14.1, 14.3, 14.4_
  
  - [ ] 14.2 Update ScanOrchestrator to use PluginManager
    - Replace direct detector invocation with plugin system
    - Integrate DetectionAggregator after detection
    - _Requirements: 14.4_
  
  - [ ] 14.3 Write unit tests for plugin system
    - Test detector registration
    - Test plugin retrieval
    - _Requirements: 14.1, 14.3_

- [ ] 15. Implement CostTracker
  - [ ] 15.1 Create CostTracker class
    - Implement track_request
    - Implement check_limits (max_requests only)
    - Implement get_usage
    - _Requirements: 7.1, 7.3_
  
  - [ ] 15.2 Integrate CostTracker into AttackExecutor
    - Track requests during execution
    - Abort if max_requests exceeded
    - _Requirements: 7.1_

- [ ] 16. Enhance AttackExecutor with concurrency control
  - [ ] 16.1 Add asyncio.Semaphore for concurrency limiting
    - Update execute_batch to use semaphore
    - _Requirements: 3.5, 17.3_
  
  - [ ] 16.2 Write unit tests for concurrency
    - Test max concurrent requests enforced
    - _Requirements: 3.5_

- [ ] 17. Enhance ReportGenerator with prioritization
  - [ ] 17.1 Implement prioritize_vulnerabilities
    - Sort by severity then confidence
    - _Requirements: 6.1, 6.2_
  
  - [ ] 17.2 Implement group_by_type
    - Group vulnerabilities by type
    - _Requirements: 6.1_
  
  - [ ] 17.3 Implement format_markdown
    - Create Markdown template
    - Generate human-readable report
    - _Requirements: 6.4_
  
  - [ ] 17.4 Update API to support format parameter
    - Add format query parameter to /report endpoint
    - _Requirements: 6.3, 6.4_

- [ ] 18. Implement replay endpoint
  - [ ] 18.1 Add POST /api/v1/scan/{scan_id}/replay endpoint
    - Retrieve original request from attack_responses
    - Re-execute prompt
    - Return comparison
    - _Requirements: 3.2, 12.4_
  
  - [ ] 18.2 Write integration test for replay
    - Execute scan
    - Replay specific prompt
    - Verify consistency
    - _Requirements: 3.2_

- [ ] 19. Expand Attack Library to 200+ prompts
  - [ ] 19.1 Add remaining prompt categories
    - Create role_confusion.json (50+ prompts)
    - Create data_exfiltration.json (50+ prompts)
    - Create hidden_instruction.json (50+ prompts)
    - Expand instruction_override.json to 50+ prompts
    - _Requirements: 2.1, 2.4_

- [ ] 20. Phase 2 Checkpoint - Validate expanded detection
  - Execute scan with all detectors
  - Verify aggregation works
  - Verify prioritized report
  - Test replay functionality
  - **User validation**: Ensure all tests pass, ask the user if questions arise.

---

## Phase 3: Productization (CLI + UI)

**Goal**: Add user-facing interfaces for non-API usage

**Deliverable**: CLI tool and web dashboard for scan management

### Tasks

- [ ] 21. Implement CLI
  - [ ] 21.1 Create CLI using Click library
    - Implement scan command
    - Implement status command
    - Implement report command
    - Implement list-categories command
    - Add progress indicators
    - Add error handling with exit codes
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  
  - [ ] 21.2 Write integration tests for CLI
    - Test scan command
    - Test status command
    - Test report command
    - _Requirements: 8.1, 8.3, 8.4_

- [ ] 22. Implement React UI
  - [ ] 22.1 Set up React project with TypeScript
    - Initialize React app with Vite
    - Configure TypeScript
    - Set up React Router
    - Create API client service
    - _Requirements: 10.1, 10.2_
  
  - [ ] 22.2 Implement ScanForm component
    - Create form with input fields
    - Add configuration options
    - Add form validation
    - Integrate with API
    - _Requirements: 10.1, 10.2_
  
  - [ ] 22.3 Implement ScanStatus component
    - Display scan progress
    - Show resource usage
    - Add polling for status updates
    - _Requirements: 10.5_
  
  - [ ] 22.4 Implement VulnerabilityList component
    - Create table view
    - Add severity color coding (High=red, Medium=orange, Low=yellow)
    - Add filtering by severity and type
    - Add click handlers for details
    - _Requirements: 10.3_
  
  - [ ] 22.5 Implement VulnerabilityDetail component
    - Display full vulnerability details
    - Show attack prompt and response
    - Show evidence and suggested fix
    - _Requirements: 10.4_
  
  - [ ] 22.6 Implement ScanHistory component
    - List recent scans
    - Add basic pagination
    - Add click handlers to view reports
    - _Requirements: 10.3_
  
  - [ ] 22.7 Implement SeverityBadge component
    - Color-coded badges for severity levels
    - _Requirements: 10.3_
  
  - [ ] 22.8 Create page routes
    - Home page with ScanForm
    - Scan page with status and results
    - Report page with full report view
    - History page with scan list
    - _Requirements: 10.1, 10.3_

- [ ] 23. Phase 3 Checkpoint - Validate user interfaces
  - Test CLI scan flow
  - Test UI scan flow
  - Verify filtering and history work
  - **User validation**: Ensure all tests pass, ask the user if questions arise.

---

## Phase 4: Hardening & Advanced Testing

**Goal**: Comprehensive testing, performance validation, production readiness

**Deliverable**: Production-ready system with full test coverage

### Tasks

- [ ]* 24. Implement encryption utilities
  - [ ]* 24.1 Create encryption module for API keys
    - Implement encrypt_api_key using Fernet
    - Implement decrypt_api_key
    - Load encryption key from environment variable
    - _Requirements: 1.3, 12.5, 13.1_
  
  - [ ]* 24.2 Write property test for encryption round-trip
    - **Property 1: API Key Encryption Round-Trip**
    - **Validates: Requirements 1.3, 12.5, 13.1**

- [ ]* 25. Implement LLMEvaluator (optional)
  - [ ]* 25.1 Create EvaluatorPlugin base interface
    - Define abstract methods with schemas
    - _Requirements: 14.2_
  
  - [ ]* 25.2 Implement LLMEvaluator
    - Integrate with OpenAI API
    - Create evaluation prompt template
    - Parse evaluation response
    - Handle API errors and retries
    - _Requirements: 4.4_
  
  - [ ]* 25.3 Update DetectionAggregator to handle evaluator results
    - Implement resolve_conflicts
    - _Requirements: 4.4_

- [ ]* 26. Implement authentication and rate limiting
  - [ ]* 26.1 Add authentication middleware to API
    - Implement API key validation
    - _Requirements: 9.5, 13.5_
  
  - [ ]* 26.2 Add rate limiting middleware
    - Implement per-client rate limiting
    - _Requirements: 13.4_
  
  - [ ]* 26.3 Write tests for auth and rate limiting
    - Test authentication enforcement
    - Test rate limit enforcement
    - _Requirements: 9.5, 13.4, 13.5_

- [ ]* 27. Implement database retry logic
  - [ ]* 27.1 Create database retry decorator
    - Implement exponential backoff
    - Configure max retries
    - Add logging
    - _Requirements: 16.4_

- [ ]* 28. Write comprehensive property-based tests
  - [ ]* 28.1 Set up Hypothesis generators
    - Create generators for domain objects
    - _Requirements: All_
  
  - [ ]* 28.2 Write property tests for core properties
    - **Property 2: Complete Request-Response Capture**
    - **Property 3: Scan Persistence Completeness**
    - **Property 4: Asynchronous Scan Execution**
    - **Property 5: Detection Plugin Invocation**
    - **Property 6: Pattern Detection Completeness**
    - **Property 7: Fault Tolerance Continuation**
    - **Property 8: Configuration Validation**
    - **Property 9: URL Validation**
    - **Property 10: Template Substitution**
    - **Property 11: Category Filtering**
    - **Property 12: Prompt Metadata Completeness**
    - **Property 13: Rate Limiting Enforcement**
    - **Property 14: Severity Classification**
    - **Property 15: Report Completeness**
    - **Property 16: JSON Report Round-Trip**
    - **Property 17: HTTP Error Code Correctness**
    - **Property 18: Authentication Enforcement**
    - **Property 19: Status Accuracy**
    - **Property 20: Log Sanitization**
    - **Property 21: Input Validation**
    - **Property 22: Rate Limit Enforcement**
    - **Property 23: Plugin Discovery**
    - **Property 24: Database Retry with Backoff**
    - **Property 25: Concurrent Scan Execution**
    - **Property 26: State Transition Validity**
    - **Property 27: Detection Aggregation Deduplication**
    - **Property 28: Cost Limit Enforcement**
    - **Property 29: Concurrency Limit Enforcement**
    - **Property 30: Replay Consistency**
    - _Requirements: All_

- [ ]* 29. Implement future plugin interfaces (design only)
  - [ ]* 29.1 Create RAGAuditorPlugin interface
    - _Requirements: 15.1_
  
  - [ ]* 29.2 Create AgentTesterPlugin interface
    - _Requirements: 15.2_
  
  - [ ]* 29.3 Create MonitorPlugin interface
    - _Requirements: 15.3_
  
  - [ ]* 29.4 Create RiskScorerPlugin interface
    - _Requirements: 15.4_
  
  - [ ]* 29.5 Create CompliancePlugin interface
    - _Requirements: 15.5_

- [ ]* 30. Create Docker configuration
  - [ ]* 30.1 Create Dockerfile
    - Multi-stage build
    - Install dependencies
    - Copy application code
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_
  
  - [ ]* 30.2 Create docker-compose.yml
    - Define API service
    - Define database service
    - Define UI service
    - Configure networking and volumes
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_
  
  - [ ]* 30.3 Create .env.example
    - Document all environment variables
    - _Requirements: 13.1_

- [ ]* 31. Performance and load testing
  - [ ]* 31.1 Run load tests
    - Test 100 concurrent scans
    - Verify resource usage
    - Check for memory leaks
    - _Requirements: 17.1, 17.3_
  
  - [ ]* 31.2 Run stress tests
    - Test system limits
    - Verify graceful degradation
    - _Requirements: 17.1, 17.3_

- [ ] 32. Final verification
  - Run full test suite
  - Verify all core functionality works
  - **User validation**: Ensure all tests pass, ask the user if questions arise.

---

## Notes

- **Phase 1** delivers a working MVP (scan → detect → report → API)
- **Phase 2** expands detection capabilities and improves analysis
- **Phase 3** adds user-facing interfaces (CLI + UI)
- **Phase 4** hardens the system with comprehensive testing and production features
- Tasks marked with `*` are optional and can be skipped for faster delivery
- Each task references specific requirements for traceability
- Checkpoints at end of each phase ensure incremental validation
- Property tests are concentrated in Phase 4 to avoid slowing early development
- Focus on working system first, comprehensive validation later
