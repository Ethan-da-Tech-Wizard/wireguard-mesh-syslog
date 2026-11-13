# WireGuard Mesh Syslog Receiver

A Python TCP syslog receiver for a configured private mesh, with an example rsyslog forwarding configuration and systemd service files. The receiver parses messages, checks peers against a configured allowlist, and writes peer logs.

## Explore the configuration

From the repository root:

```sh
python3 scripts/mesh_log_receiver.py --help
python3 scripts/mesh_log_receiver.py --status
```

The default bind address, subnet and allowed peers are defined in [the receiver](scripts/mesh_log_receiver.py). They are example values and must match the intended deployment. Inspect the bind address, peer mapping, log directory and permissions before starting a listener. `--bind`, `--port` and `--log-dir` configure its startup options.

The repository also contains [an rsyslog client example](rsyslog-client.conf) and [systemd unit examples](systemd/). Review their paths and security settings for your system before installation; the user service references a workspace-specific working directory.

## Security and reliability

The receiver uses TCP; port 6514 alone does not enable TLS. WireGuard or another appropriately configured secure network is needed if transport encryption is required. An IP allowlist is not a substitute for validating the full network configuration. Buffers are finite, and successful transmission does not guarantee durable storage or zero log loss.

The script falls back to a no-op stop latch if the workspace-specific `stop_latch` module is unavailable. Do not assume a standalone deployment is connected to a central stop control.

The repository includes [receiver tests](scripts/test_mesh_log_receiver.py), runnable with `python3 -m unittest discover -s scripts`. Results apply to the revision and environment tested.

## License

[MIT](LICENSE)
