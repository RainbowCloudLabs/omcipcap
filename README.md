# omcipcap

[![PyPI Version](https://img.shields.io/pypi/v/omcipcap?color=blue)](https://pypi.org/project/omcipcap/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/omcipcap?label=downloads&color=green)](https://pypi.org/project/omcipcap/)
[![GitHub Total Downloads](https://img.shields.io/github/downloads/daneshih1125/omcipcap/total?label=github%20total&color=orange)](https://github.com/daneshih1125/omcipcap/releases)
[![License](https://img.shields.io/github/license/daneshih1125/omcipcap)](https://github.com/daneshih1125/omcipcap/blob/main/LICENSE)

`omcipcap` is a professional GPON/XGS-PON OMCI Semantic Analysis Framework for ITU-T G.988 protocols. By implementing a table-driven semantic engine, it transforms raw pcap data into structured, human-readable insights—covering MIB state auditing, VLAN logic decoding, and T-CONT traffic hierarchy tracing.

## 🌟 Master Branch: AI & Automation Ready
The **Master** branch represents the latest evolution, shifting from a standalone tool to an analysis framework:
- **For AI & Programmers**: Full support for **JSON IR** (`-j / --json-output`), making it easy to pipe MIB data into AI models or automation pipelines.
- **For Field Engineers**: The legacy **v0.2.x-lts** branch remains available for on-site troubleshooting with traditional CLI outputs.
- **Dual-Mode Output**: Every command supports **Rich Print** (for human diagnosis) and **JSON** (for machine processing).

## Why Use omcipcap?

`omcipcap` is built to bridge the gap between complex raw protocol data and actionable engineering insights. It significantly reduces the time required for root-cause analysis in both lab and field environments.

![omcipcap_savetime](./examples/omcipcap_savetime.png)

> **Key Impact**: Transform hour-long manual packet tracing into seconds of automated analysis, allowing engineers to focus on fixing bugs rather than finding them.

## Features

| Command | Description | Output Modes |
|---|---|---|
| `check` | Analyze RTT, TID duplicates, and ME failures | Table / JSON |
| `mibdb` | Dump the Semantic MIB Database | Table / JSON |
| `mibdb-diff (diff)` | Compare two MIBs with semantic decoding | Table / JSON |
| `vlan-tbl` | Analyze OMCI VLAN tagging logic (Table-driven) | Table / JSON |
| `tcont-flow` | Trace T-CONT → GEM → PQ traffic hierarchy | Table / JSON |
| `topology (graphic)` | Generate interactive topology HTML | Interactive HTML / JSON |



## Project Structure

```text
.
├── LICENSE         # MIT License
├── README.md       # Project documentation
├── examples        # pcap and json samples
├── extensions      # semantic extensions
├── omci            # Core package
├── pyproject.toml  # Build system & entry points
├── tests           # Test suites
└── utils           # pcap generators

```

## Installation
```bash=
pip install omcipcap
```
## ⚡ Quick Start (No Python Required!)

### Download Pre-compiled Binaries
Get ready-to-run executables for your platform:

- **Windows (64-bit)**: [omcipcap.exe](https://github.com/daneshih1125/omcipcap/releases/latest/download/omcipcap.exe)
- **Linux (64-bit)**: [omcipcap_linux](https://github.com/daneshih1125/omcipcap/releases/latest/download/omcipcap_linux)
- **macOS (ARM64)**: [omcipcap_mac](https://github.com/daneshih1125/omcipcap/releases/latest/download/omcipcap_mac)

No Python installation required!

### Windows and Linux Usage

```bash
# Windows
omcipcap.exe check your_file.pcap

# Linux
chmod +x omcipcap_linux
./omcipcap_linux check your_file.pcap
```

## Sub-Command
### omcipcap check
Analyze a pcap file to display a summary of all OMCI packets:
```
# print all vendor, failed, late and duplicates packets
omcipcap check omcicheck_example.pcap
# get JSON output of OMCI resp failed
omcipcap check --only-failed -j omcicheck_example.pcap
```
![omcicheck](https://github.com/daneshih1125/omcipcap/blob/master/examples/omcicheck_example.png)

omcipcap check with --rtt-threshold argument
```bash
(venv) $ omcipcap check --rtt-threshold=1500 omcicheck_example.pcap
 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   No.   ID   Action            ME Class   ME Instance   Result                      RTT   Status            ME desc
 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   38    19   MIB_UPLOAD_NEXT   241        0x0001                                      0                     Reserved for vendor-specific managed entities
   40    20   MIB_UPLOAD_NEXT   350        0x0001                                      0                     Reserved for vendor-specific use
   52    26   MIB_UPLOAD_NEXT   500        0x000a                                      0                     Reserved for future standardization
   58    29   CREATE            84         0x0001        Err: INSTANCE_EXISTS   0.000033                     VLAN tagging filter data
   59    30   SET               241        0x0001                                      0                     Reserved for vendor-specific managed entities
   60    30   SET               241        0x0001        Err: UNKNOWN_ME        0.000033                     Reserved for vendor-specific managed entities
   64    32   GET               257        0x0000                                      0   [TID_DUPLICATE]   ONT2-G
 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Summary: Found 2 failures, 5 Vendor packets, 1 duplicate packets, 0 late packets
```

### omcipcap mibdb
MIB Database Dump

Dump all or filtered MIB instances from a pcap.

```bash
# print all MIB infomation
omcipcap mibdb examples/omci.pcap
# print all MIB for class 84 and 171
omcipcap mibdb --class-id 84,171 examples/omci.pcap
# print JSON of MIB snapshots (MIB uploads)
omcipcap mibdb -j --only-upload examples/omci.pcap
```

#### Semantic Extensions with --semantic-dir

Customize attribute decoding with specific semantics

##### Load semantic extensions from a directory and ME 134 option decoding
```bash
omcipcap mibdb --semantic-dir ./extensions --class-id 134 input.pcap
```
##### extensions/add_me134_option.py
```python 
try:
    from omci.omcisemantic import OMCISemantic
except ImportError:
    pass


def ip_host_mode(value):
    if value & 0x1:
        return "DHCP"
    return "Static"


OMCISemantic.register(134, "IP options", ip_host_mode)
```

#### Advanced: Custom ME JSON Format
To define your own Vendor MEs for the --mib-json flag, use the following structure:
```json
{
  "355": ["HWTC 355 ME", [
    ["CPE mode", 3, "str", False],
    ["Support VOIP", 1, "u8", False]
  ]]
}
```

##### Schema and Field Definitions

The custom ME JSON configuration is a map where the top-level key represents the **ME Class ID**, and the value is a nested array containing the metadata and attribute schemas:

* **`"355"`** *(String/Integer)*: The **ME Class ID** (Managed Entity Class Identifier) defined by the vendor.
* **`"HWTC 355 ME"`** *(String)*: The human-readable **ME Name** descriptor used for CLI outputs and structured logs.
* **`Attribute Array`** *(Array of Arrays)*: A sequence of arrays defining each attribute within the ME chronologically. Each attribute descriptor must contain exactly four positional fields in the following order:

| Position | Field Name | Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | **Attribute Name** | `str` | The human-readable identifier of the specific attribute. |
| `1` | **Byte Length** | `int` | The size of the attribute field in bytes within the OMCI payload message. |
| `2` | **Data Type** | `str` | The decoding target data type. Supported types include primitive network byte representations such as `"u8"`, `"u16"`, `"u32"`, or byte sequences decoded as `"str"`. |
| `3` | **Set-By-Create** | `bool` | Indicates whether the attribute property is **Set-By-Create** (SBC). Set to `True` if the attribute can be configured during the `Create` action phase; set to `False` if it is read-only or modified exclusively via `Set` actions. |


#### Advanced: Filter and Decode Vendor-Specific MEs with Custom Semantics
The combination of `--only-vendor`, `--mib-json`, and `--semantic-dir` allows you to isolate proprietary vendor behaviors, apply custom schemas, and inject high-level semantics into raw data dumps.

```bash
omcipcap mibdb --only-vendor examples/mibdb_vendor.pcap \
    --mib-json examples/mibdb_vendor.json \
    --semantic-dir examples/mibdb_vendor

                              OMCI MIB Database Snapshot
 ────────────────────────────────────────────────────────────────────────────────────
  Class ID   ME Name                            Inst ID   Attributes (Semantic View)
 ────────────────────────────────────────────────────────────────────────────────────
     65300   Reserved for vendor-specific use         1   CTC: CTC
                                                          attribute 2: 0x1
                                                          attribute 3: 0x1
                                                          attribute 4: Disabled
 ────────────────────────────────────────────────────────────────────────────────────
     65400   Reserved for vendor-specific use         1   FW Verion: v1.0.5
                                                          Health Check: Enabled
 ────────────────────────────────────────────────────────────────────────────────────
```


### omcipcap mibdb-diff
 Analyze two pcap files to identify differences in MIB provisioning
```bash
# Compare MIB snapshots between two pcaps, only compare MIB upload MIBs by default
omcipcap mibdb-diff mib_vendor_v1.pcap mib_vendor_v2.pcap
# Compare MIB snapshots between two pcaps with user defined MIB
omcipcap mibdb-diff mib_vendor_v1.pcap mib_vendor_v2.pcap --mib-json examples/vendor_355.json
# Compare Full provision MIB between two pcaps
omcipcap mibdb-diff --full ont1.pcap ont2.pcap
# Compare full MIB provisioning between two PCAPs for Class 84 and 171, and output JSON
omcipcap diff -j --full --class-id=84,171 ont1.pcap ont2.pcap
```

Example Output
When comparing a vendor-specific configuration (Class 355), omcidiff provides a clear view of the state change:
```Plaintext
(venv) $ omcipcap mibdb-diff mib_vendor_v1.pcap mib_vendor_v2.pcap --mib-json examples/vendor_355.json
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   Status         ME Name (ID)                                           Inst   Attribute          Pcap 1     Pcap 2
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   MODIFIED       Reserved for vendor-specific use (355)                  0x0   CPE mode           HGU        SFU
   MODIFIED       Reserved for vendor-specific use (355)                  0x0   Support VOIP       0x1        0x0
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Summary: Added: 0, Removed: 0, Modified: 2
```


### omcipcap topology 
```
omcipcap topology omci.pcap -o example.html
```
![PPTP](https://github.com/daneshih1125/omcipcap/blob/master/examples/pptp_graphic.png)
![IPHOST](https://github.com/daneshih1125/omcipcap/blob/master/examples/iphost_graphic.png)

### omcipcap vlan-tbl
```
omcipcap vlan-tbl omci.pcap
```
List All ME 171 instances and detail of VLAN table
![omcivlan](https://github.com/daneshih1125/omcipcap/blob/master/examples/omcivlan.png)

### omcipcap tcont-flow
```
omcipcap tcont-flow single_unit_1_tont_2_gem.pcap
```
Traces the complete upstream traffic hierarchy from T-CONT → GEM Port → Priority Queue and displays bandwidth/scheduling parameters in a tree view.

Example Output:
```plaintext
(venv) $ omcipcap tcont-flow single_unit_1_tont_2_gem.pcap
GPON T-CONT Flow Analysis
├── T-CONT 32768 (alloc-id=1000)
│   ├── GEM 1001
│   │   ├── [US] PQ 32775 → up:CIR=0.128Mbps/PIR=9953.28Mbps
│   │   └── [DS] PQ 0 → Priority 0 dn:Unrestricted
│   └── GEM 1002
│       ├── [US] PQ 32768 → up:CIR=0.128Mbps/PIR=100Mbps
│       └── [DS] PQ 6 → Priority 6 dn:Unrestricted
└── T-CONT 32769 (Unassigned)
(venv) $
```

Each T-CONT entry shows:
- **alloc-id**: The Alloc-ID assigned by the OLT; `Unassigned` means the T-CONT has not been activated (Alloc-ID = 0xFFFF).
- **GEM ports**: All GEM Port Network CTPs bound to this T-CONT.
- **[US] PQ**: Upstream Priority Queue with CIR/PIR bandwidth limits.
- **[DS] PQ**: Downstream Priority Queue with scheduling priority.

## Disclaimer
this software is for educational and network debugging purposes only. The author (daneshih1125) provides this software "as is" without warranty of any kind. 

- The users are solely responsible for ensuring that they have the legal right and proper authorization to capture, process, and analyze any network packets (pcap/log) used with this tool.
- The author shall not be held liable for any data breaches, compliance violations (such as GDPR, PDPA), leakage of trade secrets, or security incidents caused by the users processing sensitive or production network data with this tool or exporting data to third-party AI models.

## License & Copyright
**Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
Licensed under the MIT License.**
