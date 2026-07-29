#!/bin/sh
[ -d ${HOME}/.local/omcipcap ] && rm -rf ${HOME}/.local/omcipcap
[ -d ${HOME}/RAG_TEST ] && rm -rf ${HOME}/RAG_TEST
omcipcap ai rag init --profile workstation --dir ${HOME}/RAG_TEST 2>/dev/null

omcipcap ai rag ingest --issue-md case_01_olt_disply_confi_fail.md \
  --case-id case01 \
  case_01_olt_disply_confi_fail.pcap 2>/dev/null

omcipcap ai rag ingest --issue-md case_02_olt_disply_confi_fail_vendor.md \
  --case-id case02 \
  case_02_golden_d001_vendor_ok.pcap 2>/dev/null

omcipcap ai rag ingest --issue-md case_03_second_gem_vlan_rule_missing.md \
  --case-id case03 \
  case_03_second_gem_vlan_rule_missing.pcap 2>/dev/null

omcipcap ai rag ingest --issue-md case_04_10g_uni_qos_mapping_error.md \
  --case-id case04 \
  case_04_qos_applied_1g_failure.pcap 2>/dev/null
