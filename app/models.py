from pydantic import BaseModel, Field
from typing import Optional, Literal


class FieldDef(BaseModel):
    name: str
    length_rule: Literal["fixed", "ref", "until"] = "fixed"
    length_value: Optional[int] = None
    length_ref_field: Optional[str] = None
    until_byte: Optional[str] = None
    data_type: Literal[
        "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le", "bytes", "ascii"
    ] = "bytes"
    condition_field: Optional[str] = None
    condition_value: Optional[str] = None


class TemplateCreate(BaseModel):
    name: str
    description: str = ""
    fields: list[FieldDef]


class TemplateUpdate(BaseModel):
    description: Optional[str] = None
    fields: list[FieldDef]


class TemplateOut(BaseModel):
    id: int
    name: str
    description: str
    fields: list[FieldDef]
    created_at: str


class TemplateVersionOut(BaseModel):
    id: int
    template_id: int
    version: int
    name: str
    description: str
    fields: list[FieldDef]
    created_at: str


class TemplateVersionSummary(BaseModel):
    version: int
    name: str
    description: str
    created_at: str
    field_count: int


class SampleCreate(BaseModel):
    name: str
    hex_data: str
    note: str = ""


class SampleOut(BaseModel):
    id: int
    name: str
    hex_data: str
    byte_length: int
    entropy: float
    note: str
    created_at: str


class ParsedField(BaseModel):
    name: str
    hex: str
    value: Optional[str] = None
    offset: int
    length: int
    status: Literal["ok", "skipped", "parse_error"] = "ok"
    error: Optional[str] = None


class ParseResult(BaseModel):
    template_id: int
    sample_id: int
    template_version: int = 1
    fields: list[ParsedField]
    coverage_percent: float
    covered_bytes: int
    total_bytes: int
    uncovered_ranges: list[list[int]]


class BatchValidateRequest(BaseModel):
    template_id: int
    sample_ids: list[int]
    template_version: Optional[int] = None


class BatchValidateResult(BaseModel):
    template_id: int
    template_version: int
    total_samples: int
    success_count: int
    success_rate: float
    avg_coverage: float
    field_error_ranking: list[dict]
    details: list[ParseResult]


class FieldDiffValue(BaseModel):
    field_name: str
    a_value: Optional[str]
    b_value: Optional[str]
    a_hex: str
    b_hex: str
    a_status: Literal["ok", "skipped", "parse_error"]
    b_status: Literal["ok", "skipped", "parse_error"]
    has_parse_error: bool


class FieldDiffOnly(BaseModel):
    field_name: str
    value: Optional[str]
    hex: str
    status: Literal["ok", "skipped", "parse_error"]
    error: Optional[str]


class CompareRequest(BaseModel):
    template_id: int
    sample_a_id: int
    sample_b_id: int
    template_version: Optional[int] = None


class CompareResult(BaseModel):
    template_id: int
    template_version: int
    sample_a_id: int
    sample_b_id: int
    different_fields: list[FieldDiffValue]
    only_a_fields: list[FieldDiffOnly]
    only_b_fields: list[FieldDiffOnly]
    parse_result_a: ParseResult
    parse_result_b: ParseResult


# ============ Session Models ============

class SessionCreate(BaseModel):
    name: str
    template_id: int
    note: str = ""


class SessionOut(BaseModel):
    id: int
    name: str
    template_id: int
    template_version: int
    note: str
    frame_count: int
    created_at: str


class FrameCreate(BaseModel):
    hex_data: str
    direction: Literal["request", "response"]
    relative_timestamp_ms: int


class FrameOut(BaseModel):
    id: int
    session_id: int
    seq: int
    hex_data: str
    byte_length: int
    direction: Literal["request", "response"]
    relative_timestamp_ms: int
    parse_result: Optional[ParseResult] = None


class FrameParseResultOut(BaseModel):
    frame_id: int
    parse_result: ParseResult


class PairStatus(str):
    pass


class SessionPair(BaseModel):
    pair_id: int
    request_frame: Optional[FrameOut] = None
    response_frame: Optional[FrameOut] = None
    status: Literal["complete", "unanswered", "unsolicited"]
    response_delay_ms: Optional[int] = None


class SessionPairView(BaseModel):
    session_id: int
    pairs: list[SessionPair]
    orphan_frames: list[FrameOut]


class FieldValueDistribution(BaseModel):
    field_name: str
    values: dict[str, int]


class SessionStats(BaseModel):
    session_id: int
    total_frames: int
    request_count: int
    response_count: int
    avg_response_delay_ms: Optional[float]
    max_response_delay_ms: Optional[int]
    unanswered_count: int
    unsolicited_count: int
    field_distributions: list[FieldValueDistribution]


class PlaybackControl(BaseModel):
    action: Literal["start", "pause", "resume", "seek", "stop"]
    speed: Optional[float] = Field(default=None, ge=0.25, le=10.0)
    seek_to_ms: Optional[int] = Field(default=None, ge=0)


class FuzzStrategy(str):
    pass


class FuzzGenerateRequest(BaseModel):
    template_id: int
    count: int = Field(default=30, ge=1, le=100, description="Number of messages to generate, max 100")
    strategy_distribution: Optional[dict[str, float]] = Field(
        default=None,
        description="Distribution of strategies: normal, boundary, malformed. Sum must be 1.0"
    )
    template_version: Optional[int] = None


class FuzzGeneratedSample(BaseModel):
    sample_id: int
    name: str
    hex_data: str
    strategy: Literal["normal", "boundary", "malformed"]
    parse_result: Optional[ParseResult] = None


class FuzzStrategyStats(BaseModel):
    strategy: Literal["normal", "boundary", "malformed"]
    total: int
    success_count: int
    success_rate: float
    avg_coverage: float
    min_coverage: float
    max_coverage: float


class FuzzTemplateDefect(BaseModel):
    sample_name: str
    sample_id: int
    field_name: str
    error: str
    hex_data: str


class FuzzReport(BaseModel):
    template_id: int
    template_version: int
    template_name: str
    total_generated: int
    strategy_stats: list[FuzzStrategyStats]
    field_error_ranking: list[dict]
    coverage_overview: dict
    template_defects: list[FuzzTemplateDefect]
    samples: list[FuzzGeneratedSample]


class FingerprintCreate(BaseModel):
    offset: int
    expected_hex: str
    match_type: Literal["exact", "mask"] = "exact"
    mask_hex: Optional[str] = None


class FingerprintOut(BaseModel):
    id: int
    template_id: int
    offset: int
    expected_hex: str
    match_type: str
    mask_hex: Optional[str] = None
    created_at: str


class RecognizeRequest(BaseModel):
    hex_data: str


class RecognizedTemplate(BaseModel):
    template_id: int
    template_name: str
    total_rules: int
    matched_rules: int
    is_full_match: bool
    confidence: Optional[int] = None


class RecognizeResult(BaseModel):
    matches: list[RecognizedTemplate]


class SmartParseRequest(BaseModel):
    hex_data: str


class SmartParseResult(BaseModel):
    status: Literal["success", "ambiguous", "failed"]
    parse_result: Optional[ParseResult] = None
    candidates: Optional[list[RecognizedTemplate]] = None
    message: Optional[str] = None


# ============ Analysis Models ============

class ByteHeatmapRequest(BaseModel):
    sample_ids: list[int] = Field(..., min_length=2, max_length=50)


class ByteHeatmapEntry(BaseModel):
    offset: int
    unique_count: int
    mode_value: str
    mode_count: int
    is_fixed: bool
    total_samples: int
    missing_count: int


class ByteHeatmapResult(BaseModel):
    sample_ids: list[int]
    max_length: int
    sample_lengths: dict[int, int]
    total_samples: int
    heatmap: list[ByteHeatmapEntry]


class FieldMutationRequest(BaseModel):
    sample_ids: list[int] = Field(..., min_length=2, max_length=50)
    template_id: int
    template_version: Optional[int] = None


class FieldMutationEntry(BaseModel):
    field_name: str
    unique_count: int
    mode_value: Optional[str]
    mode_count: int
    distribution: dict[str, int]
    mutation_rate: float
    total_samples: int


class FieldMutationResult(BaseModel):
    template_id: int
    template_version: int
    sample_ids: list[int]
    skipped_count: int
    skipped_ids: list[int]
    total_analyzed: int
    fields: list[FieldMutationEntry]


class FixedHeaderRequest(BaseModel):
    sample_ids: list[int] = Field(..., min_length=2, max_length=50)
    min_length: int = Field(default=2, ge=2, description="Minimum consecutive fixed bytes to qualify as a fixed header region")


class FixedHeaderRegion(BaseModel):
    start_offset: int
    end_offset: int
    length: int
    fixed_hex: str


class FixedHeaderResult(BaseModel):
    sample_ids: list[int]
    total_samples: int
    max_length: int
    regions: list[FixedHeaderRegion]


# ============ State Machine Models ============

class StateType(str):
    pass


class StateCreate(BaseModel):
    name: str
    state_type: Literal["initial", "intermediate", "terminal"]


class StateOut(BaseModel):
    id: int
    state_machine_id: int
    name: str
    state_type: Literal["initial", "intermediate", "terminal"]


class TransitionCreate(BaseModel):
    from_state_name: str
    to_state_name: str
    trigger_field: str
    trigger_value: str
    direction_constraint: Literal["request", "response", "both"] = "both"


class TransitionOut(BaseModel):
    id: int
    state_machine_id: int
    from_state_id: int
    to_state_id: int
    from_state_name: str
    to_state_name: str
    trigger_field: str
    trigger_value: str
    direction_constraint: Literal["request", "response", "both"]


class StateMachineCreate(BaseModel):
    template_id: int
    name: str
    description: str = ""
    states: list[StateCreate]
    transitions: list[TransitionCreate]


class StateMachineUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    states: Optional[list[StateCreate]] = None
    transitions: Optional[list[TransitionCreate]] = None


class StateMachineOut(BaseModel):
    id: int
    template_id: int
    name: str
    description: str
    state_count: int
    transition_count: int
    created_at: str


class StateMachineDetailOut(BaseModel):
    id: int
    template_id: int
    name: str
    description: str
    states: list[StateOut]
    transitions: list[TransitionOut]
    created_at: str


class ViolationFrame(BaseModel):
    frame_seq: int
    current_state: str
    expected_transitions: list[dict]
    actual_field_value: Optional[str]
    actual_direction: str


class StateTransitionHistoryEntry(BaseModel):
    step: int
    from_state: str
    to_state: str
    frame_seq: int
    trigger_field: str
    trigger_value: str


class ValidationResult(BaseModel):
    session_id: int
    state_machine_id: int
    final_state: Optional[str]
    reached_terminal: bool
    can_validate: bool
    violation_count: int
    violations: list[ViolationFrame]
    transition_history: list[StateTransitionHistoryEntry]
    total_frames: int


class CandidateState(BaseModel):
    name: str
    state_type: Literal["initial", "intermediate", "terminal"]
    trigger_field_value: str


class CandidateTransition(BaseModel):
    from_state_name: str
    to_state_name: str
    trigger_field: str
    trigger_value: str
    direction_constraint: Literal["request", "response", "both"]


class InferenceResult(BaseModel):
    session_id: int
    template_id: int
    trigger_field: str
    states: list[CandidateState]
    transitions: list[CandidateTransition]
    total_frames: int
    status: Literal["candidate"] = "candidate"


# ============ Fragment Reassembly Models ============

class FragmentGroupCreate(BaseModel):
    name: str
    template_id: int
    template_version: int | None = None
    reassembly_strategy: Literal["sequential", "length_prefix"] = "sequential"
    note: str = ""


class FragmentGroupOut(BaseModel):
    id: int
    name: str
    template_id: int
    template_version: int
    reassembly_strategy: str
    note: str
    fragment_count: int
    created_at: str


class FragmentGroupDetailOut(BaseModel):
    id: int
    name: str
    template_id: int
    template_version: int
    reassembly_strategy: str
    note: str
    fragments: list["FragmentOut"]
    created_at: str


class FragmentAddRequest(BaseModel):
    seq_num: int = Field(..., ge=1, description="Fragment sequence number, starting from 1")
    sample_id: int


class FragmentOut(BaseModel):
    id: int
    group_id: int
    seq_num: int
    sample_id: int
    sample_name: str | None = None
    sample_byte_length: int | None = None
    created_at: str


class FragmentContribution(BaseModel):
    seq_num: int
    sample_id: int
    start_offset: int
    end_offset: int
    is_damaged: bool = False
    damage_reason: str | None = None


class ReassembleResult(BaseModel):
    group_id: int
    reassembled_hex: str
    total_bytes: int
    parse_result: ParseResult
    fragment_contributions: list[FragmentContribution]
    damaged_fragments: list[int]


class DetectRequest(BaseModel):
    sample_ids: list[int] = Field(..., min_length=2, max_length=20, description="Sample IDs to try assembling")
    template_id: int
    template_version: int | None = None


class DetectCandidate(BaseModel):
    order: list[int]
    coverage_percent: float
    parse_result: ParseResult
    reassembled_hex: str


class DetectResult(BaseModel):
    template_id: int
    template_version: int
    total_samples: int
    candidates_attempted: int
    best_candidate: DetectCandidate
    all_candidates: list[DetectCandidate]


FragmentGroupDetailOut.model_rebuild()


# ============ Alert Rule Models ============

NUMERIC_TYPES = {"uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"}
STRING_TYPES = {"bytes", "ascii"}


class ConditionCompare(BaseModel):
    type: Literal["compare"] = "compare"
    field: str
    op: Literal["==", "!=", ">", "<", ">=", "<="]
    value: str | int | float | None = None
    field_ref: str | None = None


class ConditionLogical(BaseModel):
    type: Literal["and", "or", "not"]
    conditions: list["ConditionExpr"]


ConditionExpr = ConditionCompare | ConditionLogical
ConditionLogical.model_rebuild()


class AlertRuleCreate(BaseModel):
    template_id: int
    name: str
    severity: Literal["info", "warning", "critical"]
    expression: ConditionExpr


class AlertRuleOut(BaseModel):
    id: int
    template_id: int
    name: str
    severity: Literal["info", "warning", "critical"]
    expression: dict
    created_at: str


class TriggeredAlert(BaseModel):
    rule_id: int
    rule_name: str
    severity: Literal["info", "warning", "critical"]
    field_values: dict[str, str | int | float | None]


class DetectAlertsRequest(BaseModel):
    sample_id: int
    template_id: int | None = None


class DetectAlertsResult(BaseModel):
    sample_id: int
    template_id: int
    template_version: int
    parse_result: ParseResult
    triggered_alerts: list[TriggeredAlert]


class ScanAlertsRequest(BaseModel):
    sample_ids: list[int]
    template_id: int


class CriticalAlertDetail(BaseModel):
    sample_id: int
    rule_name: str
    field_values: dict[str, str | int | float | None]


class ScanAlertsResult(BaseModel):
    template_id: int
    template_version: int
    total_samples: int
    processed_samples: int
    skipped_sample_ids: list[int]
    samples_with_alerts: int
    rule_trigger_ranking: list[dict]
    severity_stats: dict[str, int]
    critical_alerts: list[CriticalAlertDetail]


class DryRunRequest(BaseModel):
    sample_id: int
    template_id: int | None = None
    expression: ConditionExpr


class ConditionEvaluation(BaseModel):
    description: str
    result: bool | None


class DryRunResult(BaseModel):
    sample_id: int
    template_id: int
    template_version: int
    triggered: bool
    field_values: dict[str, str | int | float | None]
    evaluations: list[ConditionEvaluation]
