"""Reserved adapter boundary for future eBPF telemetry integration.

Real readers are intentionally not enabled in M1; they must normalize events
into ``NetworkEvent`` and report lost ring-buffer events separately.
"""

