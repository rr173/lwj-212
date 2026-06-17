from pydantic import BaseModel, Field
from typing import Optional, Literal


class DeviceCreate(BaseModel):
    device_sn: str = Field(..., min_length=1, max_length=64)
    device_model: str = Field(..., min_length=1, max_length=64)
    firmware_version: str = Field(..., min_length=1, max_length=32)
    group_tag: str = Field(default="", max_length=64)
    online_status: Literal["online", "offline"] = "online"


class DeviceBatchCreate(BaseModel):
    devices: list[DeviceCreate] = Field(..., min_length=1, max_length=50)


class DeviceOut(BaseModel):
    id: int
    device_sn: str
    device_model: str
    firmware_version: str
    group_tag: str
    online_status: str
    created_at: str


class PlanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    target_version: str = Field(..., min_length=1, max_length=32)
    device_model: str = Field(..., min_length=1, max_length=64)
    filter_group: str = Field(default="", max_length=64)
    filter_version_min: str = Field(default="", max_length=32)
    filter_version_max: str = Field(default="", max_length=32)
    strategy: Literal["full", "batch"]
    batch_size: int = Field(default=0, ge=0, le=100)
    batch_interval: int = Field(default=0, ge=0)
    failure_threshold: float = Field(..., ge=0.01, le=1.0)
    rollback_version: str = Field(default="", max_length=32)


class PlanOut(BaseModel):
    id: int
    name: str
    target_version: str
    device_model: str
    filter_group: str
    filter_version_min: str
    filter_version_max: str
    strategy: str
    batch_size: int
    batch_interval: int
    failure_threshold: float
    rollback_version: str
    status: str
    current_batch: int
    total_devices: int
    created_at: str


class DeviceReport(BaseModel):
    device_id: int
    success: bool
    failure_reason: str = Field(default="", max_length=256)


class PlanDashboard(BaseModel):
    plan_id: int
    plan_name: str
    status: str
    total_devices: int
    pushed_count: int
    success_count: int
    failed_count: int
    pending_count: int
    upgrading_count: int
    skipped_count: int
    pending_rollback_count: int
    failure_rate: float
    current_batch: int


class PlanDeviceOut(BaseModel):
    id: int
    plan_id: int
    device_id: int
    device_sn: str
    device_model: str
    firmware_version: str
    group_tag: str
    online_status: str
    status: str
    target_version: str
    failure_reason: str
    batch_number: int
