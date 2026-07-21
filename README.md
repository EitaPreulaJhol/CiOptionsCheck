# CiOptions Check — Code Integrity Options Viewer

A lightweight Windows native utility that queries and displays Code Integrity (CI) configuration and related system security state using direct NT system call interfaces.

## Features

- **CI Options Inspection** — Polls `NtQuerySystemInformation(SystemCodeIntegrityInformation)` and decodes every CI option flag (HVCI, KMCI, UMCI, WHQL enforcement, ELAM, VBS, flight build, etc.).
- **Diagnostics Tab** — Shows OS version (via `RtlGetVersion` — bypasses the `GetVersionEx` app-compat shim), Secure Boot status, Hypervisor presence, and Virtualization-Based Security (VBS) state.
- **Registry Fallback** — Secure Boot falls back to `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State` when the NT API fails.

## Requirements

- Windows 10 / 11 (or Windows 8+ with appropriate CI features).
- Microsoft Visual C++ compiler (MSVC) with Windows SDK (currently using MSVC v140, Windows SDK 10.0.22621.0).

## Internals

The tool uses `NtQuerySystemInformation` (class `SystemCodeIntegrityInformation` = 103, plus classes 123, 132, 157, 196) to read kernel-mode security state without WMI or the CIM layer.
No admin elevation is required for these queries on a standard system.
