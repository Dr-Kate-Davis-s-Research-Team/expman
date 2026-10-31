# Experiment Manager (expman)

This tool exists because cyber-physical malware testing is messy by nature. You run risky or variable experiments, you pause and revert machines, you change datasets, and you often repeat runs days or weeks later. If you do not record exactly what was used and how the environment looked, the results are easy to misinterpret and almost impossible to defend.

`expman` gives you a clear, human-readable experiment record/manifest for every experiment. The experiment record/manifest is your evidence trail: it shows the inputs, the environment, the safety posture, and the artifacts you produced. It also lets you prove that nothing drifted between runs.

## What This Does

This project builds a reproducible lab workflow. Every experiment writes a record/manifest that answers these questions:

1. What did we run?
2. What was the environment and safety posture?
3. What inputs were used and are they unchanged?
4. What artifacts were produced?
5. Can we repeat it later and get the same conditions?

This is the foundation for credible cyber-physical testing, post-mortem analysis, and safe reuse.

## Features

- **Experiment Initialization**  
  Generates `experiment_manifest.json` with hashes, environment metadata, snapshots, and safety flags.

- **Drift Detection**  
  Recomputes hashes of datasets, configs, snapshot metadata, and artifacts to catch silent changes.

- **Safety & Reproducibility Records**  
  Captures network isolation, privilege level, random seed, and one-click reset confirmation.

- **Environment Capture**  
  Records OS, Python version, machine identity, Git commit/dirty state, and optional `pip freeze`.

- **Artifact Indexing**  
  Adds PCAPs, logs, exports, and other evidence to the experiment record/manifest.

- **Lifecycle Event Logging**  
  Records deploy, pause, kill-switch, revert, and related events for auditability.

## What The Manifest Captures

- **Experiment identity**: unique ID, UTC creation time, host, and operator.
- **Inputs**: dataset and attack config paths with SHA-256 hashes.
- **Environment**: OS, Python, machine type, Git commit/dirty state, and optional package list.
- **Safety posture**: isolation mode, privilege level, and reset confirmation.
- **Snapshot tracking**: pre/post snapshot names and optional snapshot metadata hash.
- **Reproducibility**: random seed and consistent hashing across files/directories.
- **Artifacts**: PCAPs, logs, and exports with hashes and sizes.
- **Lifecycle events**: deploy, pause, kill-switch, revert, and shutdown events.

## Installation

Requires Python 3.11+.

Development install (runs from source):
```bash
cd expman
pip install -e .
```

Standard install:
```bash
pip install .
```

## Directory Layout

- `sample_data/` holds example datasets and configs for local testing.
- `experiments/` is where experiment outputs and experiment record/manifests are stored.
- `src/` contains the CLI and core logic.
- `tests/` contains unit tests.

## Usage

### 1. Initialize an Experiment
Creates a new directory with a record/manifest.

```bash
python -m expman init \
  --out-dir ./experiments/dnp3_before \
  --vm-id "vm-lab-01" \
  --snapshot-pre "clean-state" \
  --snapshot-post "infected-state" \
  --network-isolation "air-gapped" \
  --privilege-level "admin" \
  --random-seed 12345 \
  --dataset-path ./sample_data/dnp3_before.csv \
  --attack-config-path ./sample_data/config.json \
  --capture-pip-freeze \
  --confirm-reset
```

### 2. Verify an Experiment
Checks if the current environment and inputs still match the experiment record/manifest.

```bash
python -m expman verify --manifest ./experiments/dnp3_before/experiment_manifest.json
```

You can also verify drift against an "after" dataset:
```bash
python -m expman verify \
  --manifest ./experiments/dnp3_before/experiment_manifest.json \
  --dataset-path ./sample_data/dnp3_after.csv
```

You can also verify specific values:
```bash
python -m expman verify \
  --manifest ./experiments/dnp3_before/experiment_manifest.json \
  --vm-snapshot-hash "abc123" \
  --network-isolation "air-gapped" \
  --privilege-level "admin"
```

### 3. Record Artifacts
Add evidence files (PCAPs, logs, exports) after the run.

```bash
python -m expman record-artifact \
  --manifest ./experiments/dnp3_before/experiment_manifest.json \
  --artifact-path ./experiments/dnp3_before/captures/exp_001.pcap \
  --kind pcap
```

### 4. Record Lifecycle Events
Capture actions like deploy, pause, kill-switch, or revert.

```bash
python -m expman record-event \
  --manifest ./experiments/dnp3_before/experiment_manifest.json \
  --event-type revert \
  --notes "Reverted to clean-state after payload test"
```

## Testing

From the `expman` directory:
```bash
pytest
```

From the repo root:
```bash
pytest expman/tests
```

## Why This Matters

In a malware-like experiment, tiny changes can completely alter outcomes. A dataset edit, a different VM snapshot, or a modified config will silently shift your results. The experiment record/manifest is the source of truth that ties everything together and proves what actually happened, so you can repeat the experiment or explain it with confidence.
