# Problem

The ONT comes online successfully, but the OLT always reports the service state as **Configure Failed**.

# Root-Cause

Before provisioning HGU services, the OLT locks the PPTP UNI by setting the Administrative State to **Lock**. After service provisioning is complete, the OLT unlocks the PPTP UNI by setting the Administrative State to **Unlock (0)**.

When the OLT sends the OMCI Set request to change the PPTP UNI Administrative State to **Unlock (0)**, the ONT does not respond in time. The OMCI response is delayed by more than one second, causing the OLT to report the service provisioning as **Configure Failed**.

# Trigger-Condition

- The OLT provisions HGU services.
- The ONT comes online and enters the service provisioning process.

# How-To-Identify

Using the same OLT configuration and service profile:

- **B001 ONT** completes provisioning successfully.
- `omcipcap check b001.pcap` reports no late response for the PPTP UNI Administrative State Set operation.
- `omcipcap check a001.pcap` reports a late response (>1 second) to the OLT Set request for the PPTP UNI Administrative State.

# Solution

Fix the issue in the ONT firmware.

The ONT enables the Ethernet interface through an I²C command. In some cases, the command execution time exceeds one second.

When processing the PPTP UNI Administrative State Set request, the ONT should acknowledge the OMCI request immediately using an asynchronous mechanism. If enabling the Ethernet interface later fails, the ONT should report the actual failure through the appropriate alarm mechanism instead of delaying the OMCI response.

# Environment

- OLT: A001 OLT
- ONT: A001 ONT
