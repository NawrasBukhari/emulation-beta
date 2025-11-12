# UAV Communication Emulation and Anomaly Detection

A lightweight Python simulation that emulates UAV (Unmanned Aerial Vehicle) communication channels and detects anomalies in network traffic patterns. The system generates telemetry packets, injects various types of anomalies, and analyzes them using statistical methods.

## Overview

This module simulates a UAV communication network where multiple drones send telemetry data. The system can detect anomalies such as packet loss, malformed payloads, spoofed IDs, and statistical irregularities in network behavior.

## Requirements

Python 3.7 or higher. The module uses only standard library modules:
- asyncio
- base64
- json
- logging
- random
- collections
- datetime
- pathlib

No external dependencies required.

## Quick Start

Run the simulation directly:

```bash
python uav_emulation.py
```

This executes a default simulation with 100 cycles, generating packets and detecting anomalies.

## How It Works

The simulation consists of three main components:

### ChannelEmulator

Generates encrypted telemetry packets from simulated UAVs. Each packet contains:
- UAV identifier
- Timestamp
- Telemetry data (altitude, speed, heading, battery level)
- Base64-encoded payload
- Checksum

The emulator randomly injects three types of anomalies:
- **Packet loss**: Packets that never arrive
- **Malformed payload**: Packets with incorrect checksums
- **Spoofed ID**: Packets from unauthorized UAV identifiers

### AnomalyDetector

Analyzes incoming packets and extracts statistical features:
- Latency variance between packets
- Checksum mismatch rate
- Repeated ID frequency patterns

The detector triggers alerts when statistical thresholds are exceeded, helping identify network issues and potential security threats.

### SimulationRunner

Orchestrates the entire simulation process:
- Runs multiple cycles of packet generation and analysis
- Logs all detected anomalies to timestamped files
- Generates a comprehensive JSON summary report

## Output Files

The simulation creates a `logs` directory with two types of files:

1. **Anomaly Logs** (`anomalies_YYYYMMDD_HHMMSS.log`): Detailed timestamped log of all anomalies detected during the simulation run.

2. **Analysis Report** (`analysis_run_YYYYMMDD.json`): JSON summary containing:
   - Total packets processed
   - Checksum mismatch statistics
   - Latency metrics
   - Alert counts by type and severity
   - Complete list of all alerts
   - Simulation duration and timing information

## Customization

You can modify the simulation parameters by editing the `main()` function:

```python
async def main():
    runner = SimulationRunner(
        cycles=200,        # Number of simulation cycles
        seed=42,           # Random seed for reproducibility
        anomaly_rate=0.15  # Probability of anomaly injection (0.0 to 1.0)
    )
    await runner.run()
```

You can also adjust detection thresholds in the `AnomalyDetector` initialization:
- `latency_threshold`: Maximum acceptable latency variance
- `checksum_threshold`: Maximum acceptable checksum mismatch rate
- `repeat_id_threshold`: Maximum acceptable ID repetition frequency

## Reproducibility

The simulation uses deterministic random seeds by default, ensuring that runs with the same seed produce identical results. This is useful for testing and debugging.

## Use Cases

- Testing anomaly detection algorithms
- Simulating network conditions for UAV communication systems
- Evaluating security monitoring capabilities
- Training and validation of network analysis tools

