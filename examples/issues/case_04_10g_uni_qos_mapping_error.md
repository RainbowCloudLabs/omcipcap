# Problem

The ONT has a 10G Ethernet UNI.

When the OLT provisions the upstream traffic descriptor with:

- CIR: 0.128 Mbps
- PIR: 9953.28 Mbps

the actual upstream throughput is limited to approximately 1 Gbps.

When the upstream traffic descriptor is not provisioned and the upstream queue is shown as Unrestricted, the same service can reach close to 10 Gbps.

# Root-Cause

The OMCI provisioning itself is valid.

The issue is caused by an incorrect traffic mapping implementation in the ONT SoC vendor software.

Possible implementation errors include:

- Mapping the traffic descriptor to a 1G UNI traffic path
- Using the wrong physical port index
- Applying a 1G shaping profile to the 10G UNI
- Incorrect mapping between the OMCI priority queue and the SoC hardware queue
- Not handling 10G UNI interfaces correctly when converting the OMCI PIR value to the hardware shaper configuration

As a result, applying a nominal PIR of 9953.28 Mbps incorrectly limits the upstream traffic to approximately 1 Gbps.

# Trigger-Condition

- The OLT provisions PPTP UNI service with 10G bandwidth.
- The ONT comes online and enters the service provisioning process.

# How-To-Identify

Run:

    omcipcap tcont-flow <capture.pcap>

Failing capture:

    GEM 1001
    [US] PQ 32775 → up:CIR=0.128Mbps/PIR=9953.28Mbps

Observed throughput:

    Approximately 1 Gbps

Comparison capture:

    GEM 1001
    [US] PQ 32796 → up:Unrestricted

Observed throughput:

    Close to 10 Gbps

The traffic descriptor values in the OMCI capture appear correct, so the failure is likely in the ONT SoC traffic mapping or hardware shaper configuration.

# Solution

Fix the ONT SoC traffic mapping implementation for the 10G UNI.

Verify that:

- The OMCI priority queue maps to the correct 10G UNI hardware queue
- The correct physical port index is used
- The PIR value is converted using the correct units and range
- No 1G-specific limit is applied to the 10G UNI
- The traffic descriptor is attached to the intended GEM and UNI traffic path

# Workaround

Do not apply the upstream traffic descriptor.

This leaves the upstream traffic unrestricted and allows the service to reach close to 10 Gbps.

The workaround removes bandwidth enforcement and should not be treated as the final solution.

# Environment

- Single 10G Ethernet UNI
- VLAN 10
- T-CONT 32768
- Alloc-ID 1000
- GEM Port 1001
