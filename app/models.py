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


class TemplateOut(BaseModel):
    id: int
    name: str
    description: str
    fields: list[FieldDef]
    created_at: str


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
    fields: list[ParsedField]
    coverage_percent: float
    covered_bytes: int
    total_bytes: int
    uncovered_ranges: list[list[int]]


class BatchValidateRequest(BaseModel):
    template_id: int
    sample_ids: list[int]


class BatchValidateResult(BaseModel):
    template_id: int
    total_samples: int
    success_count: int
    success_rate: float
    avg_coverage: float
    field_error_ranking: list[dict]
    details: list[ParseResult]
