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
