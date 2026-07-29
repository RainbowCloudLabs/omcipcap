# Problem

The ONT comes online successfully, and all OMCI commands return successful responses. However, traffic for the second service VLAN does not pass.

The first service using VLAN 100 works normally, while the second service using VLAN 200 is unavailable.

# Root-Cause

The OLT creates two GEM Port service paths that share the same T-CONT, but it does not provision the corresponding ME 171 VLAN rule for the second GEM Port service.

The expected ME 171 configuration contains two service rules:

- VLAN 100 service rule
- VLAN 200 service rule

In the failing capture, only the VLAN 100 rule is provisioned. The VLAN 200 rule is missing.

As a result, traffic for the second service cannot be classified and forwarded through its expected GEM Port, even though the GEM Port itself has already been created.

# Trigger-Condition

- The OLT provisions two services on the same ONT.
- Both services share the same T-CONT.
- Each service uses a different GEM Port and VLAN.
- The OLT omits the ME 171 rule for the second service.

# How-To-Identify

Inspect the VLAN rules using:

```bash
omcipcap vlan-tbl failing.pcap
```

The failing capture contains only the VLAN 100 service rule.

The failing capture is missing the ME 171 rule associated with VLAN 200.

The OMCI transaction itself does not report a command failure because the missing rule was never sent by the OLT.

# Solution

Correct the OLT provisioning logic so that it generates and sends the ME 171 VLAN rule for every configured GEM Port service.

For this scenario, the OLT must provision both:

- VLAN 100 rule for the first GEM Port
- VLAN 200 rule for the second GEM Port

After reprovisioning, verify that both rules are present in the ME 171 table and that traffic for both services passes successfully.

# Environment

- OLT: A001 OLT
- ONT: SFU ONT
- T-CONT: Shared by two GEM Port services
- Service 1: VLAN 100
- Service 2: VLAN 200
