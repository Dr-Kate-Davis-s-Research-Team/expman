from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4
import platform as _platform
import getpass

from pydantic import BaseModel, Field

def get_utc_now():
    return datetime.now(timezone.utc)

class NetworkIsolationStatus(str, Enum):
    AIR_GAPPED = "air-gapped"
    SIMULATED_WAN = "simulated-wan"

class PrivilegeLevel(str, Enum):
    USER = "user"
    ADMIN = "admin"
    PLC_EMULATION = "plc-emulation"

class ToolInfo(BaseModel):
    name: str = "expman"
    version: str = "1.1.0"
    python: str = Field(default_factory=_platform.python_version)

class EnvironmentInfo(BaseModel):
    os: str = Field(default_factory=_platform.system)
    os_release: str = Field(default_factory=_platform.release)
    os_version: str = Field(default_factory=_platform.version)
    platform: str = Field(default_factory=_platform.platform)
    machine: str = Field(default_factory=_platform.machine)
    python: str = Field(default_factory=_platform.python_version)
    git_commit: Optional[str] = None
    git_dirty: Optional[bool] = None
    pip_freeze: Optional[List[str]] = None

class SnapshotInfo(BaseModel):
    pre_attack: str
    post_attack: str

class SnapshotMetadataInfo(BaseModel):
    path: str
    hash_alg: str = "sha256"
    hash: str

class DatasetInfo(BaseModel):
    path: str
    hash_alg: str = "sha256"
    hash: str

class AttackConfigInfo(BaseModel):
    path: str
    hash_alg: str = "sha256"
    checksum: str

class ArtifactInfo(BaseModel):
    path: str
    hash_alg: str = "sha256"
    hash: str
    kind: str
    size_bytes: int

class LifecycleEventType(str, Enum):
    DEPLOY = "deploy"
    PAUSE = "pause"
    RESUME = "resume"
    KILL_SWITCH = "kill-switch"
    REVERT = "revert"
    SHUTDOWN = "shutdown"

class LifecycleEvent(BaseModel):
    event_type: LifecycleEventType
    timestamp_utc: datetime = Field(default_factory=get_utc_now)
    notes: Optional[str] = None

class ExperimentManifest(BaseModel):
    manifest_version: str = "1.1.0"
    experiment_id: UUID = Field(default_factory=uuid4)
    created_utc: datetime = Field(default_factory=get_utc_now)
    created_by: str = Field(default_factory=getpass.getuser)
    host: str = Field(default_factory=_platform.node)
    
    tool: ToolInfo = Field(default_factory=ToolInfo)
    environment: EnvironmentInfo = Field(default_factory=EnvironmentInfo)
    
    # Dashboard Metadata
    vm_or_container_id: str
    snapshot: SnapshotInfo
    network_isolation_status: NetworkIsolationStatus
    privilege_level: PrivilegeLevel
    
    # Safety & Reproducibility
    random_seed: int
    dataset: DatasetInfo
    vm_snapshot_hash: str
    snapshot_metadata: Optional[SnapshotMetadataInfo] = None
    attack_configuration: AttackConfigInfo
    one_click_reset_confirmation: bool
    
    # Optional
    notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    artifacts: List[ArtifactInfo] = Field(default_factory=list)
    lifecycle_events: List[LifecycleEvent] = Field(default_factory=list)
