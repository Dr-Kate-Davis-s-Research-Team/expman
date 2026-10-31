import typer
import logging
import json
import os
from pathlib import Path
from typing import Optional, List
import pydantic

from .schema import (
    ExperimentManifest,
    NetworkIsolationStatus,
    PrivilegeLevel,
    SnapshotInfo,
    SnapshotMetadataInfo,
    DatasetInfo,
    AttackConfigInfo,
    EnvironmentInfo,
    ArtifactInfo,
    LifecycleEvent,
    LifecycleEventType
)
from .hashing import compute_hash, compute_file_hash
from .utils import atomic_write_json, get_git_info, get_pip_freeze

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("expman")

app = typer.Typer(help="Experiment Manager CLI for Cyber-Physical Malware Sandbox", add_completion=False)

def _load_manifest(path: Path) -> ExperimentManifest:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return ExperimentManifest(**data)

def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            file_path = Path(root) / name
            if file_path.is_symlink():
                continue
            try:
                total += file_path.stat().st_size
            except OSError:
                continue
    return total

@app.command()
def init(
    out_dir: Path = typer.Option(..., help="Output directory for the experiment"),
    vm_id: str = typer.Option(..., help="VM or Container ID"),
    snapshot_pre: str = typer.Option(..., help="Pre-attack snapshot name"),
    snapshot_post: str = typer.Option(..., help="Post-attack snapshot name"),
    network_isolation: NetworkIsolationStatus = typer.Option(..., help="Network isolation status"),
    privilege_level: PrivilegeLevel = typer.Option(..., help="Privilege level"),
    random_seed: int = typer.Option(..., help="Random seed"),
    dataset_path: Path = typer.Option(..., help="Path to dataset file or directory"),
    attack_config_path: Path = typer.Option(..., help="Path to attack config file"),
    vm_snapshot_hash: Optional[str] = typer.Option(None, help="Hash of VM snapshot (if known)"),
    snapshot_metadata_path: Optional[Path] = typer.Option(None, help="Path to snapshot metadata file to hash"),
    confirm_reset: bool = typer.Option(False, help="Confirm one-click reset capability"),
    capture_pip_freeze: bool = typer.Option(False, help="Include pip freeze output in the manifest"),
    notes: Optional[str] = typer.Option(None, help="Optional notes"),
    tags: Optional[List[str]] = typer.Option(None, help="Optional tags")
):
    """
    Initialize a new experiment and generate experiment_manifest.json.
    """
    try:
        if not out_dir.exists():
            out_dir.mkdir(parents=True, exist_ok=True)

        typer.secho(f"Hashing dataset: {dataset_path} ...", fg=typer.colors.BLUE)
        dataset_hash = compute_hash(str(dataset_path))

        typer.secho(f"Hashing attack config: {attack_config_path} ...", fg=typer.colors.BLUE)
        config_hash = compute_file_hash(str(attack_config_path))

        final_vm_hash = vm_snapshot_hash
        snapshot_metadata = None
        if snapshot_metadata_path:
            typer.secho(f"Hashing snapshot metadata: {snapshot_metadata_path} ...", fg=typer.colors.BLUE)
            snapshot_hash = compute_file_hash(str(snapshot_metadata_path))
            snapshot_metadata = SnapshotMetadataInfo(
                path=str(snapshot_metadata_path.absolute()),
                hash=snapshot_hash
            )
            if not final_vm_hash:
                final_vm_hash = snapshot_hash

        if not final_vm_hash:
            final_vm_hash = "UNKNOWN"
            typer.secho("Warning: No VM snapshot hash provided.", fg=typer.colors.YELLOW)

        git_commit, git_dirty = get_git_info(Path.cwd())
        pip_freeze = get_pip_freeze() if capture_pip_freeze else None
        environment = EnvironmentInfo(
            git_commit=git_commit,
            git_dirty=git_dirty,
            pip_freeze=pip_freeze
        )

        manifest = ExperimentManifest(
            vm_or_container_id=vm_id,
            snapshot=SnapshotInfo(pre_attack=snapshot_pre, post_attack=snapshot_post),
            network_isolation_status=network_isolation,
            privilege_level=privilege_level,
            random_seed=random_seed,
            dataset=DatasetInfo(
                path=str(dataset_path.absolute()),
                hash=dataset_hash
            ),
            snapshot_metadata=snapshot_metadata,
            attack_configuration=AttackConfigInfo(
                path=str(attack_config_path.absolute()),
                checksum=config_hash
            ),
            vm_snapshot_hash=final_vm_hash,
            one_click_reset_confirmation=confirm_reset,
            notes=notes,
            tags=tags or [],
            environment=environment
        )

        manifest_path = out_dir / "experiment_manifest.json"
        atomic_write_json(manifest.model_dump(mode='json'), str(manifest_path))

        typer.secho(f"OK: Experiment initialized: {manifest_path}", fg=typer.colors.GREEN, bold=True)

    except (FileNotFoundError, PermissionError) as e:
        typer.secho(f"ERROR: File Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"ERROR: Fatal Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command()
def verify(
    manifest_path: Path = typer.Option(..., "--manifest", help="Path to experiment_manifest.json"),
    dataset_path: Optional[Path] = typer.Option(None, help="Override dataset path"),
    attack_config_path: Optional[Path] = typer.Option(None, help="Override attack config path"),
    snapshot_metadata_path: Optional[Path] = typer.Option(None, help="Override snapshot metadata path"),
    vm_snapshot_hash: Optional[str] = typer.Option(None, help="Compare against a known VM snapshot hash"),
    network_isolation: Optional[NetworkIsolationStatus] = typer.Option(None, help="Verify network isolation value"),
    privilege_level: Optional[PrivilegeLevel] = typer.Option(None, help="Verify privilege level value"),
    verify_artifacts: bool = typer.Option(True, help="Verify recorded artifacts")
):
    """
    Verify the integrity of an experiment against its manifest.
    """
    if not manifest_path.exists():
        typer.secho(f"ERROR: Manifest not found: {manifest_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        manifest = _load_manifest(manifest_path)
        typer.secho(f"Verifying Experiment: {manifest.experiment_id}", bold=True)

        errors = []

        target_dataset = dataset_path if dataset_path else Path(manifest.dataset.path)
        if not target_dataset.exists():
            errors.append(f"Dataset not found: {target_dataset}")
        else:
            typer.secho(f"  Checking dataset: {target_dataset} ...", nl=False)
            current_hash = compute_hash(str(target_dataset))
            if current_hash != manifest.dataset.hash:
                typer.secho(" FAIL", fg=typer.colors.RED)
                errors.append(f"Dataset integrity mismatch! Expected {manifest.dataset.hash}, got {current_hash}")
            else:
                typer.secho(" OK", fg=typer.colors.GREEN)

        target_config = attack_config_path if attack_config_path else Path(manifest.attack_configuration.path)
        if not target_config.exists():
            errors.append(f"Attack config not found: {target_config}")
        else:
            typer.secho(f"  Checking config: {target_config} ...", nl=False)
            current_config_hash = compute_file_hash(str(target_config))
            if current_config_hash != manifest.attack_configuration.checksum:
                typer.secho(" FAIL", fg=typer.colors.RED)
                errors.append(f"Config mismatch! Expected {manifest.attack_configuration.checksum}, got {current_config_hash}")
            else:
                typer.secho(" OK", fg=typer.colors.GREEN)

        if manifest.snapshot_metadata or snapshot_metadata_path:
            target_snapshot_meta = snapshot_metadata_path
            if not target_snapshot_meta and manifest.snapshot_metadata:
                target_snapshot_meta = Path(manifest.snapshot_metadata.path)
            if target_snapshot_meta and not target_snapshot_meta.exists():
                errors.append(f"Snapshot metadata not found: {target_snapshot_meta}")
            elif target_snapshot_meta:
                typer.secho(f"  Checking snapshot metadata: {target_snapshot_meta} ...", nl=False)
                current_snapshot_hash = compute_file_hash(str(target_snapshot_meta))
                expected_snapshot_hash = manifest.snapshot_metadata.hash if manifest.snapshot_metadata else manifest.vm_snapshot_hash
                if current_snapshot_hash != expected_snapshot_hash:
                    typer.secho(" FAIL", fg=typer.colors.RED)
                    errors.append(
                        f"Snapshot metadata mismatch! Expected {expected_snapshot_hash}, got {current_snapshot_hash}"
                    )
                else:
                    typer.secho(" OK", fg=typer.colors.GREEN)

        if vm_snapshot_hash and vm_snapshot_hash != manifest.vm_snapshot_hash:
            errors.append(
                f"VM snapshot hash mismatch! Expected {manifest.vm_snapshot_hash}, got {vm_snapshot_hash}"
            )

        if network_isolation and network_isolation != manifest.network_isolation_status:
            errors.append(
                f"Network isolation mismatch! Expected {manifest.network_isolation_status}, got {network_isolation}"
            )

        if privilege_level and privilege_level != manifest.privilege_level:
            errors.append(
                f"Privilege level mismatch! Expected {manifest.privilege_level}, got {privilege_level}"
            )

        if verify_artifacts and manifest.artifacts:
            for artifact in manifest.artifacts:
                artifact_path = Path(artifact.path)
                if not artifact_path.exists():
                    errors.append(f"Artifact not found: {artifact_path}")
                    continue
                typer.secho(f"  Checking artifact: {artifact_path} ...", nl=False)
                current_artifact_hash = compute_hash(str(artifact_path))
                if current_artifact_hash != artifact.hash:
                    typer.secho(" FAIL", fg=typer.colors.RED)
                    errors.append(
                        f"Artifact mismatch! {artifact.path} expected {artifact.hash}, got {current_artifact_hash}"
                    )
                else:
                    typer.secho(" OK", fg=typer.colors.GREEN)

        if errors:
            typer.secho("\nERROR: Verification FAILED:", fg=typer.colors.RED, bold=True)
            for err in errors:
                typer.echo(f"  - {err}")
            raise typer.Exit(code=1)
        else:
            typer.secho("\nOK: All checks passed. Experiment is consistent.", fg=typer.colors.GREEN, bold=True)

    except json.JSONDecodeError as e:
        typer.secho(f"ERROR: Invalid JSON in manifest: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except pydantic.ValidationError as e:
        typer.secho(f"ERROR: Manifest Schema Error:\n{e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"ERROR: Usage Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command("record-artifact")
def record_artifact(
    manifest_path: Path = typer.Option(..., "--manifest", help="Path to experiment_manifest.json"),
    artifact_path: Path = typer.Option(..., help="Path to artifact file or directory"),
    kind: str = typer.Option(..., help="Artifact type (pcap, log, json, csv, etc.)")
):
    """
    Add an artifact entry to the manifest.
    """
    if not manifest_path.exists():
        typer.secho(f"ERROR: Manifest not found: {manifest_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if not artifact_path.exists():
        typer.secho(f"ERROR: Artifact not found: {artifact_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        manifest = _load_manifest(manifest_path)
        artifact_hash = compute_hash(str(artifact_path))
        size_bytes = _path_size(artifact_path)

        manifest.artifacts.append(
            ArtifactInfo(
                path=str(artifact_path.absolute()),
                hash=artifact_hash,
                kind=kind,
                size_bytes=size_bytes
            )
        )
        atomic_write_json(manifest.model_dump(mode='json'), str(manifest_path))
        typer.secho(f"OK: Recorded artifact: {artifact_path}", fg=typer.colors.GREEN, bold=True)
    except Exception as e:
        typer.secho(f"ERROR: Usage Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

@app.command("record-event")
def record_event(
    manifest_path: Path = typer.Option(..., "--manifest", help="Path to experiment_manifest.json"),
    event_type: LifecycleEventType = typer.Option(..., help="Event type"),
    notes: Optional[str] = typer.Option(None, help="Optional notes")
):
    """
    Record a lifecycle event (deploy, pause, kill-switch, revert, etc.).
    """
    if not manifest_path.exists():
        typer.secho(f"ERROR: Manifest not found: {manifest_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        manifest = _load_manifest(manifest_path)
        manifest.lifecycle_events.append(LifecycleEvent(event_type=event_type, notes=notes))
        atomic_write_json(manifest.model_dump(mode='json'), str(manifest_path))
        typer.secho(f"OK: Recorded event: {event_type}", fg=typer.colors.GREEN, bold=True)
    except Exception as e:
        typer.secho(f"ERROR: Usage Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
