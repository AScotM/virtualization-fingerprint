# Virtualization Fingerprint

Read-only Linux virtualization diagnostics in a single Go source file. Designed for KVM/QEMU guests and compatible with other common hypervisors. Uses the Go standard library only.

## Requirements

- Linux with `/proc` and `/sys` mounted
- Go 1.22 or later for building
- ANSI-compatible terminal for colored text
- Basic inspection does not require root; restricted files are reported as unavailable

## Build

```sh
go build -trimpath -ldflags='-s -w' -o virtualization-fingerprint main.go
```

## Usage

```sh
./virtualization-fingerprint
./virtualization-fingerprint inspect
./virtualization-fingerprint identity
./virtualization-fingerprint cpu
./virtualization-fingerprint virtio
./virtualization-fingerprint clock
./virtualization-fingerprint storage
./virtualization-fingerprint network
./virtualization-fingerprint memory
./virtualization-fingerprint security
./virtualization-fingerprint integration
./virtualization-fingerprint report -format json -output server1.json
./virtualization-fingerprint report -format csv -output server1.csv
./virtualization-fingerprint compare -before server1-before.json -after server1-after.json
./virtualization-fingerprint inspect -no-color
```

## Modules

| Module | Evidence |
| --- | --- |
| identity | DMI manufacturer, product, BIOS, hypervisor sysfs |
| cpu | Visible logical processors, vendor/model, selected feature flags |
| virtio | Virtio bus entries and kernel modules |
| clock | Current/available clocksource, uptime, RTC |
| storage | Block devices, model/vendor, scheduler, rotational indicator |
| network | Interfaces, addresses, MTU, driver and queue count |
| memory | Total memory, huge pages, THP, memory topology |
| security | Lockdown, LSM, KSM, TDX/SEV device presence, mitigations |
| integration | Selected guest agent services and virtio ports |

## Reporting

JSON reports have schema version 1. `compare` matches findings by module/key and reports added, removed and changed values. The generated timestamp is excluded from comparisons. Reports may include hostnames, MAC addresses and hardware identifiers: review before sharing publicly.

## Interpretation

The detection confidence score is a *heuristic*, not a probability. DMI strings, virtual drivers, clocksource names and CPU flags are guest-visible evidence that can be masked, spoofed or shared by multiple hypervisors. Virtio does not prove KVM/QEMU, and the absence of a hypervisor signature does not prove bare metal. Confidential-computing device presence does not prove guest attestation or isolation. No kernel module is loaded, no device is modified, and no privileged host interface is required.

The `-root` option reads from an alternative filesystem tree for basic offline inspection, but service inspection is skipped and host metadata can still reflect the running environment. It is not a fully isolated forensic filesystem parser.

## License

GPL-3.0-or-later. See LICENSE.
