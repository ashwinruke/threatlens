"""A tiny, hand-made ATT&CK bundle with the same shape as MITRE's real file.

It includes the awkward cases the parser must handle: a retired group replaced by
another (twice, as a chain), a deprecated relationship, a relationship pointing at a
retired object, markdown links, citations, and <code> blocks.
"""


def ref(external_id, kind_path):
    return [{"source_name": "mitre-attack", "external_id": external_id,
             "url": f"https://attack.mitre.org/{kind_path}/{external_id.replace('.', '/')}"},
            {"source_name": "Example Report", "url": "https://example.org/report", "description": "A report."}]


def rel(rel_id, source, target, kind="uses", **extra):
    return {"type": "relationship", "id": f"relationship--{rel_id}", "relationship_type": kind,
            "source_ref": source, "target_ref": target, "description": extra.pop("description", ""), **extra}


TACTIC = {"type": "x-mitre-tactic", "id": "x-mitre-tactic--cred", "name": "Credential Access",
          "x_mitre_shortname": "credential-access", "external_references": ref("TA0006", "tactics")}
PARENT = {"type": "attack-pattern", "id": "attack-pattern--dump", "name": "OS Credential Dumping",
          "external_references": ref("T1003", "techniques"), "x_mitre_platforms": ["Windows", "Linux"],
          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
          "description": "Adversaries may dump credentials. (Citation: Some Report 2024)"}
SUB = {"type": "attack-pattern", "id": "attack-pattern--lsass", "name": "LSASS Memory",
       "x_mitre_is_subtechnique": True, "external_references": ref("T1003.001", "techniques"),
       "x_mitre_platforms": ["Windows"],
       "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
       "description": "Tools like [Mimikatz](https://attack.mitre.org/software/S0002) run "
                      "<code>sekurlsa::logonpasswords</code> or <code>net user <username></code>."}
GROUP = {"type": "intrusion-set", "id": "intrusion-set--volt", "name": "Volt Typhoon",
         "aliases": ["Volt Typhoon", "BRONZE SILHOUETTE", "Vanguard Panda"],
         "external_references": ref("G1017", "groups"), "description": "A state-sponsored actor."}
OLD_GROUP = {"type": "intrusion-set", "id": "intrusion-set--old", "name": "Old Name", "revoked": True,
             "external_references": ref("G0074", "groups")}
MIDDLE_GROUP = {"type": "intrusion-set", "id": "intrusion-set--middle", "name": "Middle Name", "revoked": True,
                "external_references": ref("G0075", "groups")}
MALWARE = {"type": "malware", "id": "malware--versamem", "name": "VersaMem", "x_mitre_aliases": ["VersaMem"],
           "external_references": ref("S1154", "software"), "x_mitre_platforms": ["Linux"]}
TOOL = {"type": "tool", "id": "tool--mimikatz", "name": "Mimikatz", "external_references": ref("S0002", "software")}
CAMPAIGN = {"type": "campaign", "id": "campaign--kv", "name": "KV Botnet Activity", "aliases": ["KV Botnet Activity"],
            "first_seen": "2022-10-01T00:00:00.000Z", "last_seen": "2024-01-01T00:00:00.000Z",
            "external_references": ref("C0035", "campaigns")}
MITIGATION = {"type": "course-of-action", "id": "course-of-action--cap", "name": "Credential Access Protection",
              "external_references": ref("M1043", "mitigations")}
DEPRECATED_TOOL = {"type": "tool", "id": "tool--gone", "name": "Gone Tool", "x_mitre_deprecated": True,
                   "external_references": ref("S9999", "software")}
ANALYTIC = {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a1", "name": "Ignored"}

BUNDLE = {"type": "bundle", "objects": [
    {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "19.2"},
    TACTIC, PARENT, SUB, GROUP, OLD_GROUP, MIDDLE_GROUP, MALWARE, TOOL, CAMPAIGN, MITIGATION, DEPRECATED_TOOL, ANALYTIC,
    rel("1", SUB["id"], PARENT["id"], "subtechnique-of"),
    rel("2", GROUP["id"], SUB["id"], description="[Volt Typhoon](https://attack.mitre.org/groups/G1017) dumped LSASS."),
    rel("3", GROUP["id"], TOOL["id"]),
    rel("4", GROUP["id"], MALWARE["id"]),
    rel("5", TOOL["id"], SUB["id"]),
    rel("6", CAMPAIGN["id"], GROUP["id"], "attributed-to"),
    rel("7", MITIGATION["id"], SUB["id"], "mitigates"),
    rel("8", GROUP["id"], PARENT["id"], x_mitre_deprecated=True),  # deprecated: dropped
    rel("9", GROUP["id"], DEPRECATED_TOOL["id"]),  # points at a deprecated object: dropped
    rel("10", OLD_GROUP["id"], MIDDLE_GROUP["id"], "revoked-by"),  # G0074 -> G0075 -> G1017
    rel("11", MIDDLE_GROUP["id"], GROUP["id"], "revoked-by"),
    rel("12", "x-mitre-detection-strategy--d", SUB["id"], "detects"),  # not kept
]}
