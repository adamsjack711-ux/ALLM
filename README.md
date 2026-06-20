# ALLM — AI-Attack Detector

A defender-side detector that flags AI-agent-driven activity in security
telemetry and classifies it against MITRE ATT&CK. It learns the behavioral shape
of an AI-driven intrusion (machine-speed pivoting, action-ordering structure,
accelerating cadence), not static signatures.

See [`ai-attack-detector-v1-plan.md`](./ai-attack-detector-v1-plan.md) for the
roadmap and current status.

## Quick start

```bash
pip install numpy pandas scikit-learn torch

python detector_v0.py --synthetic     # aggregate baseline
python detector_v05.py                # GRU over event sequences
python detector_v1.py --synthetic     # ATT&CK multi-label (risk + per-technique + spans)
python inspect_dataset.py --demo      # dataset column-mapping helper
python adapter_winlogs.py --demo      # Windows/Sysmon event-log adapter
```

Everything runs end-to-end on synthetic/demo data with no network. Models are
evaluated with PR-AUC and false-positives-per-hour (never accuracy) on a
campaign-level split.
