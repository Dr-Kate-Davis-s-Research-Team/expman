import pytest
from typer.testing import CliRunner
from pathlib import Path
import json
from expman.cli import app

runner = CliRunner()

def test_init_creates_manifest(tmp_path):
    dataset = tmp_path / "data.csv"
    dataset.write_text("some data")
    
    config = tmp_path / "attack.yaml"
    config.write_text("config: true")
    
    out_dir = tmp_path / "exp_01"
    
    result = runner.invoke(app, [
        "init",
        "--out-dir", str(out_dir),
        "--vm-id", "vm-123",
        "--snapshot-pre", "clean-snap",
        "--snapshot-post", "infected-snap",
        "--network-isolation", "air-gapped",
        "--privilege-level", "admin",
        "--random-seed", "42",
        "--dataset-path", str(dataset),
        "--attack-config-path", str(config),
        "--confirm-reset"
    ])
    
    assert result.exit_code == 0
    assert (out_dir / "experiment_manifest.json").exists()
    
    with open(out_dir / "experiment_manifest.json") as f:
        data = json.load(f)
        assert data["vm_or_container_id"] == "vm-123"
        assert data["one_click_reset_confirmation"] is True

def test_verify_success(tmp_path):
    dataset = tmp_path / "data.csv"
    dataset.write_text("some data")
    config = tmp_path / "attack.yaml"
    config.write_text("config: true")
    out_dir = tmp_path / "exp_01"
    
    runner.invoke(app, [
        "init",
        "--out-dir", str(out_dir),
        "--vm-id", "vm-123",
        "--snapshot-pre", "clean-snap",
        "--snapshot-post", "infected-snap",
        "--network-isolation", "air-gapped",
        "--privilege-level", "admin",
        "--random-seed", "42",
        "--dataset-path", str(dataset),
        "--attack-config-path", str(config)
    ])
    
    input_manifest = out_dir / "experiment_manifest.json"
    result = runner.invoke(app, ["verify", "--manifest", str(input_manifest)])
    assert result.exit_code == 0
    assert "All checks passed" in result.stdout

def test_verify_drift_detection(tmp_path):
    dataset = tmp_path / "data.csv"
    dataset.write_text("original data")
    config = tmp_path / "attack.yaml"
    config.write_text("config: true")
    out_dir = tmp_path / "exp_01"
    
    runner.invoke(app, [
        "init",
        "--out-dir", str(out_dir),
        "--vm-id", "vm-123",
        "--snapshot-pre", "clean-snap",
        "--snapshot-post", "infected-snap",
        "--network-isolation", "air-gapped",
        "--privilege-level", "admin",
        "--random-seed", "42",
        "--dataset-path", str(dataset),
        "--attack-config-path", str(config)
    ])
    
    dataset.write_text("modified data")
    
    input_manifest = out_dir / "experiment_manifest.json"
    result = runner.invoke(app, ["verify", "--manifest", str(input_manifest)])
    
    assert result.exit_code == 1
    assert "Verification FAILED" in result.stdout
    assert "Dataset integrity mismatch" in result.stdout

def test_record_artifact_and_verify(tmp_path):
    dataset = tmp_path / "data.csv"
    dataset.write_text("some data")
    config = tmp_path / "attack.yaml"
    config.write_text("config: true")
    out_dir = tmp_path / "exp_01"

    runner.invoke(app, [
        "init",
        "--out-dir", str(out_dir),
        "--vm-id", "vm-123",
        "--snapshot-pre", "clean-snap",
        "--snapshot-post", "infected-snap",
        "--network-isolation", "air-gapped",
        "--privilege-level", "admin",
        "--random-seed", "42",
        "--dataset-path", str(dataset),
        "--attack-config-path", str(config)
    ])

    artifact = tmp_path / "capture.pcap"
    artifact.write_text("pcap-bytes")

    manifest = out_dir / "experiment_manifest.json"
    result = runner.invoke(app, [
        "record-artifact",
        "--manifest", str(manifest),
        "--artifact-path", str(artifact),
        "--kind", "pcap"
    ])
    assert result.exit_code == 0

    verify_ok = runner.invoke(app, ["verify", "--manifest", str(manifest)])
    assert verify_ok.exit_code == 0

    artifact.write_text("pcap-bytes-modified")
    verify_fail = runner.invoke(app, ["verify", "--manifest", str(manifest)])
    assert verify_fail.exit_code == 1
    assert "Artifact mismatch" in verify_fail.stdout

def test_record_event(tmp_path):
    dataset = tmp_path / "data.csv"
    dataset.write_text("some data")
    config = tmp_path / "attack.yaml"
    config.write_text("config: true")
    out_dir = tmp_path / "exp_01"

    runner.invoke(app, [
        "init",
        "--out-dir", str(out_dir),
        "--vm-id", "vm-123",
        "--snapshot-pre", "clean-snap",
        "--snapshot-post", "infected-snap",
        "--network-isolation", "air-gapped",
        "--privilege-level", "admin",
        "--random-seed", "42",
        "--dataset-path", str(dataset),
        "--attack-config-path", str(config)
    ])

    manifest = out_dir / "experiment_manifest.json"
    result = runner.invoke(app, [
        "record-event",
        "--manifest", str(manifest),
        "--event-type", "revert",
        "--notes", "reverted to clean snapshot"
    ])
    assert result.exit_code == 0

    with open(manifest) as f:
        data = json.load(f)
        assert len(data["lifecycle_events"]) == 1
        assert data["lifecycle_events"][0]["event_type"] == "revert"
