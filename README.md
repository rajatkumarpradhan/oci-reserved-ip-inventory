# oci-reserved-ip-inventory

**Category: custom portfolio tool.** Pure Python command-line auditor. It does **not** wire any
built-in OCI services together - it is the *custom* project in its daily pair (the built-in
services project is `oci-ootb-apigw-usage-plan-check`).

## The problem

Reserved public IPs are the stable addresses your DNS, firewall rules and partner allowlists
point at. But they are also easy to forget: an IP reserved for a project that shipped, attached
to an instance that was later terminated, or sitting unattached for months. Nobody notices
because nothing pages you for a forgotten address - until DNS points somewhere unexpected or a
"stable" address gets attached to the wrong thing. This tool audits an **offline inventory
snapshot** and flags the addresses that need a decision.

## What it does

Reads a JSON snapshot (schema below, synthetic samples included) and applies four rules:

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| IP001 | HIGH | A reserved IP's `assigned_entity_id` is not in the export's known-entities list - it points at something that no longer exists in this inventory (dangling assignment). |
| IP002 | MEDIUM | A reserved IP has been unattached for more than 30 days (idle inventory nobody is using). |
| IP003 | MEDIUM | A reserved IP has no `owner` tag - nobody is accountable for keeping or releasing it. |
| IP004 | LOW | A reserved IP has no name metadata - its purpose is not recorded anywhere. |

Exit code: `2` if any HIGH finding, `1` if only MEDIUM/LOW, `0` when clean.

## Run it

```bash
python -m ip_inventory.cli samples/ips_messy.json --as-of 2026-11-17   # exits 2, all 4 rules fire
python -m ip_inventory.cli samples/ips_clean.json --as-of 2026-11-17   # exits 0
```

`--as-of` fixes the reference date so idle-age math is reproducible; omit it for today (UTC).

## Test it

```bash
python -m unittest discover -s tests -v   # 20 tests, stdlib only
```

## Snapshot schema

```json
{
  "known_entities": ["ocid1.instance.oc1..i1"],
  "reserved_ips": [
    {"ocid": "ocid1.publicip.oc1..r1", "ip_address": "129.80.1.10",
     "name": "payments-api", "created_at": "2026-01-15",
     "assigned_entity_id": "ocid1.instance.oc1..i1", "tags": {"owner": "payments-team"}}
  ]
}
```

## Honest limits

- **Offline only**: the snapshot is synthetic; nothing calls the OCI Network API or lists real
  public IPs.
- IP001 means "the target is absent from this export's entity list" - if the export is partial,
  the finding reflects the export, not the tenancy. Verify before releasing an address.
- The 30-day idle window (IP002) is a default, not OCI policy.
- No billing claims: this audits inventory hygiene and assignment integrity, not cost.
- Attachment is simplified to a single `assigned_entity_id`; OCI's private-IP/VNIC indirection
  is not modeled.

## Project status

Built as a daily portfolio project. 20 unit tests, all green locally and in CI
(`.github/workflows/ci.yml`, Python 3.10/3.11/3.12). No paid services, no live cloud calls.
