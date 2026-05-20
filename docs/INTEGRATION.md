Markdown

# Integration Guide: Enterprise TrustStore Monitoring & Automation

This guide provides operational configurations, architectural blueprints, and automated integration patterns to deploy the `check_truststore` engine across enterprise infrastructures.

---

## Prometheus Monitoring Layer (Alertmanager Integration)

When executed via CLI with the `-f status` flag, `check_truststore` exposes telemetry data blocks. This payload can be funneled into native, left-aligned time-series metrics via the **Prometheus Node Exporter Textfile Collector**.

### Automation Exporter Schema (`/etc/cron.d/truststore_exporter`)

Deploy this cron segment to automatically stream evaluated matrix properties into your metric collections every hour without syntax-breaking space indentations:

```bash
0 * * * * root check_truststore https://www.example.lan -s -O -f status | jq -r '.groups | (map(.summary.totalCertificates) | add // 0) as $total | (map(select(.groupStatus == "OK")) | length) as $ok_groups | (map(select(.groupStatus == "WARNING")) | length) as $warning_groups | (map(select(.groupStatus == "ERROR" or .groupStatus == "INVALID")) | length) as $error_groups | "truststore_total_count \($total)\ntruststore_ok_groups \($ok_groups)\ntruststore_warning_groups \($warning_groups)\ntruststore_error_groups \($error_groups)"' > /var/lib/node_exporter/textfile_collector/truststore.prom
```

### Core Alerting Rules Configuration (`prometheus/truststore_alerts.yml`)

```yaml
groups:
  - name: TrustStoreSecurityAlerts
    rules:
      - alert: TrustStoreChainErrorDetected
        expr: truststore_error_groups > 0
        for: 2m
        labels:
          severity: critical
          tier: secops
        annotations:
          summary: "Untrusted or Revoked Certificate Chain on {{ $labels.instance }}"
          description: "The check_truststore engine discovered active chain errors (e.g., signature mismatch, OS blacklist violation, or incomplete chains). Immediate remediation required."

      - alert: TrustStoreCertificatesExpiringSoon
        expr: truststore_warning_groups > 0
        for: 30m
        labels:
          severity: warning
          tier: infrastructure
        annotations:
          summary: "Expiring trust assets detected on {{ $labels.instance }}"
          description: "There are currently truststores breaching the defined operational threshold. Renew downstream authorities before validation workflows degrade."
```

## Ansible Automation Platform (AAP) Custom Module [WIP / UNTESTED]

> [!WARNING]
> **Work In Progress (WIP):** The following section describes an architectural setup designed to scale x509 compliance verification within Ansible Automation Platform (AAP) in-memory. This module configuration is currently **untested** in production and serves as a blueprint for future evaluation.

### Planned Custom Module Core (`library/check_truststore_module.py`)

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

# (C) 2024-2026 Serge van Thillo <nulleke76@gmail.com>
# GNU Lesser General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: check_truststore_module
short_description: Executes check_truststore analysis against inventory data and local playbook files.
version_added: "1.1.0"
description:
    - This module processes truststore data structures in-memory.
    - It supports both inline raw certificate content and path strings pointing to certificate files.
options:
    truststores:
        description:
            - A list of truststore definitions containing inline raw payloads or file contents.
        type: list
        required: true
    system:
        description:
            - Incorporate the host's underlying system truststore pools.
        type: bool
        default: false
    threshold:
        description:
            - Certificate expiration threshold represented in days.
        type: int
        default: 30
    max_depth:
        description:
            - Maximum recursion depth for discovering missing chain authorities.
        type: int
        default: 4
author:
    - Serge van Thillo (@nulleke76)
'''

EXAMPLES = r'''
- name: Execute truststore security verification with external files
  check_truststore_module:
    truststores: "{{ app_truststore_definitions }}"
    system: true
    threshold: 30
  register: audit_output
'''

RETURN = r'''
statistics:
    description: Summary matrix mapping evaluated certificate states.
    type: dict
    returned: always
    sample: { "ok": 5, "warning": 0, "error": 1, "total": 6 }
exit_code:
    description: Operational exit status mapped from the validation engine.
    type: int
    returned: always
    sample: 1
'''

import base64
import os
from ansible.module_utils.basic import AnsibleModule

from check_truststore.engine.repository import CertificateRepository
from check_truststore.engine.builder import TrustChainBuilder
from check_truststore.engine.models import CertificateGroup

def run_module():
    argument_spec = dict(
        truststores=dict(type='list', required=True),
        system=dict(type='bool', default=False),
        threshold=dict(type='int', default=30),
        max_depth=dict(type='int', default=4),
    )

    result = dict(
        changed=False,
        statistics=dict(),
        exit_code=0
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    try:
        repo = CertificateRepository(
            threshold=module.params['threshold'],
            system=module.params['system']
        )

        analysis_groups = []

        for t_store in module.params['truststores']:
            group_name = t_store.get('group_name', 'Unnamed Group')
            certs_payload = t_store.get('certs', [])
            
            resolved_targets = []
            
            for cert_item in certs_payload:
                raw_content = cert_item.get('content', '')
                
                # If content is missing but a file path payload is provided instead
                # Note: The file must be shipped to the target execution node or looked up
                if not raw_content and 'file' in cert_item:
                    file_path = cert_item['file']
                    if os.path.exists(file_path):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            raw_content = f.read()
                    else:
                        # Fallback case or handle error if file is unreachable on target node
                        continue

                if not raw_content:
                    continue

                # Automatically decode base64 representations if present
                if not raw_content.startswith('-----BEGIN'):
                    try:
                        raw_content = base64.b64decode(raw_content).decode('utf-8')
                    except Exception:
                        pass
                
                der_meta = repo.add_der_data(raw_content.encode('utf-8'), is_system=False)
                resolved_targets.extend(der_meta)

            if resolved_targets:
                analysis_groups.append(CertificateGroup(name=group_name, targets=resolved_targets))

        if not analysis_groups:
            module.fail_json(msg="No verifiable certificate structures could be assembled from input variables.")

        builder = TrustChainBuilder(repository=repo, **module.params)
        
        total_errors = 0
        total_warnings = 0
        total_ok = 0

        for group in analysis_groups:
            trees = builder.build(
                group.targets,
                authority_pool=repo.get_system_pool() if module.params['system'] else None,
                max_depth=module.params['max_depth']
            )
            
            def evaluate_nodes(nodes):
                nonlocal total_errors, total_warnings, total_ok
                for node in nodes:
                    if not node.is_valid:
                        total_errors += 1
                    elif node.is_expiring_soon:
                        total_warnings += 1
                    else:
                        total_ok += 1
                    if node.children:
                        evaluate_nodes(node.children)

            evaluate_nodes(trees)

        result['statistics'] = {
            'ok': total_ok,
            'warning': total_warnings,
            'error': total_errors,
            'total': total_ok + total_warnings + total_errors
        }

        if total_errors > 0:
            result['exit_code'] = 1
            module.fail_json(msg="TrustStore compliance failure: Invalid or blacklisted entries detected.", **result)
        else:
            result['exit_code'] = 0
            module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg="Internal execution engine crash: {0}".format(str(e)))

if __name__ == '__main__':
    run_module()
```

### Host Variables Schema (`host_vars/application_server.yml`)

This pattern allows repository-relative paths (resolved dynamically on the controller side via file lookups) and raw inline matrices to coexist inside unified inventory files.

```yaml
---
# Define truststore models mixing inline content and playbook-relative files
app_truststore_definitions:
  - group_name: "External API Integration Endpoint"
    certs:
      # Option A: Playbook-relative file lookups (resolved automatically on controller)
      - name: "partner_root_ca.crt"
        content: "{{ lookup('file', 'files/certs/partner_root_ca.crt') }}"
      - name: "partner_intermediate.crt"
        content: "{{ lookup('file', 'files/certs/partner_intermediate.crt') }}"
        
  - group_name: "Internal Service Mesh Layer"
    certs:
      # Option B: Standard inline content matrix representation
      - name: "internal_mesh_signer.crt"
        content: "-----BEGIN CERTIFICATE-----\nMIIFJDCCAwygAwIBAgIIZ...[truncated]...\n-----END CERTIFICATE-----"
```

### Playbook Orchestration (`verify_compliance.yml`):

```yaml
---
- name: Execute Mixed Source TrustStore Compliance Auditing
  hosts: all
  gather_facts: false
  tasks:
    - name: Analyze blended variable and file inputs in-memory
      check_truststore_module:
        truststores: "{{ app_truststore_definitions }}"
        system: true
        threshold: 30
        max_depth: 4
      register: truststore_analytics

    - name: Assert validation metrics inside AAP Controller logs
      ansible.builtin.debug:
        msg: >
          Analysis complete. 
          Total elements processed: {{ truststore_analytics.statistics.total }}.
          Status code returned by engine: {{ truststore_analytics.exit_code }}.
```

