# Problem

The C001 ONT comes online successfully, but the OLT always reports the service state as **Configure Failed**.

# Root-Cause

The C001 ONT does not upload the required vendor-specific Managed Entity.

Compared with the reference ONT, the MIB Upload is missing:

- ME Class ID: 65535
- Attribute Mask: 0xF000
- Attribute Data:
  ```
  01 33 34 35 00 00 01
  ```

Because this vendor-specific ME is absent, the OLT determines that service provisioning has failed.

# Trigger-Condition

- The OLT provisions the service.
- The C001 ONT comes online and performs MIB Upload.

# How-To-Identify

Compare the uploaded MIB with a known-good ONT:

```bash
omcipcap diff c001.pcap golden_d001.pcap
```

The comparison shows that **golden_d001.pcap** uploads vendor-specific ME **65535**, while **c001.pcap** does not.

# Solution

Update the C001 ONT firmware to upload the required vendor-specific ME during the MIB Upload procedure.

# Environment

- OLT: A001 OLT
- ONT: C001 ONT
