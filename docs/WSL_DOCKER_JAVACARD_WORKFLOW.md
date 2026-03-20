# WSL Docker JavaCard Workflow

This document records the working `Windows -> WSL Ubuntu -> Docker -> JavaCard` workflow used to build, install, and test `SatochipApplet` on the target card.

## Current environment

- Windows host repo path: `C:\Users\richa\Documents\github\SatochipApplet`
- WSL distro: `Ubuntu`
- Docker container: `stoic_nash`
- Docker image: `my-javacard-new-env`
- Repo path inside container: `/workspace/Documents/github/SatochipApplet`
- Reader used for validation: `ACS ACR1281 1S Dual Reader 00 01`
- GlobalPlatform test key: `404142434445464748494A4B4C4D4E4F`

## Quick health check

From Windows PowerShell:

```powershell
wsl.exe -d Ubuntu -- docker ps
```

Verify the Java toolchain inside the container:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash java -version
wsl.exe -d Ubuntu -- docker exec stoic_nash ant -version
```

Expected result:

- Java is available inside the container
- Ant is available inside the container

## Build the CAP

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && ant"
```

Expected result:

- `BUILD SUCCESSFUL`
- CAP written to `/workspace/Documents/github/SatochipApplet/SatoChip-3.0.4.cap`

## List card content

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && java -jar gp.jar -r 'ACS ACR1281 1S Dual Reader 00 01' --key 404142434445464748494A4B4C4D4E4F -l"
```

## Reinstall the applet

Use the clean uninstall plus install sequence:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && java -jar gp.jar -r 'ACS ACR1281 1S Dual Reader 00 01' --key 404142434445464748494A4B4C4D4E4F --uninstall SatoChip-3.0.4.cap && java -jar gp.jar -r 'ACS ACR1281 1S Dual Reader 00 01' --key 404142434445464748494A4B4C4D4E4F --install SatoChip-3.0.4.cap"
```

Observed good output:

```text
5361746F43686970 deleted.
CAP loaded
```

After install, re-check the registry:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && java -jar gp.jar -r 'ACS ACR1281 1S Dual Reader 00 01' --key 404142434445464748494A4B4C4D4E4F -l"
```

The expected applet instance is:

```text
APP: 5361746F4368697000 (SELECTABLE)
```

## List readers from inside the container

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && python3 scripts/test_ed25519.py --list-readers"
```

Observed output:

```text
[*] 0: ACS ACR1281 1S Dual Reader 00 00
[ ] 1: ACS ACR1281 1S Dual Reader 00 01
[ ] 2: ACS ACR1281 1S Dual Reader 00 02
```

Use the exact reader string in regression commands to avoid index drift.

## Run the main regressions

Recommended one-shot pipeline:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && python3 scripts/run_realcard_pipeline.py --reader 'ACS ACR1281 1S Dual Reader 00 01' --pin 123456 --setup --reset-before --debug --no-reference"
```

This runs build, CAP reinstall, the main regression, and the failure-path regression serially.

Ed25519 smoke test:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && python3 scripts/test_ed25519.py --reader 'ACS ACR1281 1S Dual Reader 00 01' --pin 123456 --setup --reset-before --debug --no-reference"
```

Full Satochip plus Ed25519 regression:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && python3 scripts/test_satochip_regression.py --reader 'ACS ACR1281 1S Dual Reader 00 01' --pin 123456 --setup --reset-before --debug --no-reference"
```

Failure-path regression:

```powershell
wsl.exe -d Ubuntu -- docker exec stoic_nash sh -c "cd /workspace/Documents/github/SatochipApplet && python3 scripts/test_sensitive_failure_paths.py --reader 'ACS ACR1281 1S Dual Reader 00 01' --pin 123456 --setup --reset-before --debug"
```

Failure-path coverage now includes:

- protected commands sent without a secure channel
- `INS_PROCESS_SECURE_CHANNEL` before initialization
- truncated secure-channel envelopes
- tampered secure-channel MAC
- even or replayed secure-channel IV
- stale secure-channel sessions after applet reselect
- `INS_SIGN_TRANSACTION` with a missing temporary BIP32 derived key
- stale-key invalidation after BIP32 reset

## Troubleshooting notes

- If `docker` is unavailable from Windows PowerShell, confirm Docker Desktop or the WSL-side daemon is running first.
- If a regression fails immediately after CAP reinstall with a transient applet select error, rerun once before assuming the AID or CAP is wrong.
- Do not run two card-facing test scripts in parallel against the same reader. Parallel runs can trigger `SCARD_W_RESET_CARD`, `0x9C21`, or secure-channel desynchronization.
- The container already contains Java and Ant. Do not rely on the Windows host `PATH` for JavaCard build validation.
- The repository path inside the container is not `/workspace/SatochipApplet`. Use `/workspace/Documents/github/SatochipApplet`.
