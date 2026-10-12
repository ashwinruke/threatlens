"""What a good knowledge search must return, checked against real ATT&CK 19.2 data.

Categories:
- exact:   IDs, names, and well-known aliases analysts actually type
- typo:    misspellings and partial names
- topic:   descriptive words that appear in the entry
- meaning: described in different words than MITRE uses. Word matching is expected
           to struggle here; this is the category embeddings would have to improve.
"""
CASES = [
    # (query, expected top result, category). A tuple of IDs means any of them is correct.
    ("G1017", "G1017", "exact"),
    ("t1059.001", "T1059.001", "exact"),
    ("Volt Typhoon", "G1017", "exact"),
    ("APT29", "G0016", "exact"),
    ("cozy bear", "G0016", "exact"),
    ("fancy bear", "G0007", "exact"),
    ("hidden cobra", "G0032", "exact"),
    ("sandworm", "G0034", "exact"),
    ("mimikatz", "S0002", "exact"),
    ("cobalt strike", "S0154", "exact"),
    ("wannacry", "S0366", "exact"),
    ("emotet", "S0367", "exact"),
    ("Operation North Star", "C0022", "exact"),
    ("credential access", "TA0006", "exact"),
    ("mimikats", "S0002", "typo"),
    ("volt typhon", "G1017", "typo"),
    ("wanacry", "S0366", "typo"),
    ("lazarus", "G0032", "typo"),
    ("cobalt", ("S0154", "G0080"), "typo"),  # Cobalt Strike or Cobalt Group: genuinely ambiguous
    ("lockbit", ("S1199", "S1202"), "typo"),  # LockBit 2.0 or 3.0
    ("dream job", "C0022", "typo"),
    ("lsass", "T1003.001", "topic"),
    ("lsass memory dumping", "T1003.001", "topic"),
    ("credential dumping", "T1003", "topic"),
    ("powershell", "T1059.001", "topic"),
    ("spearphishing attachment", "T1566.001", "topic"),
    ("scheduled task", "T1053.005", "topic"),
    ("remote desktop", "T1021.001", "topic"),
    ("encrypt files for ransom", "T1486", "meaning"),
    ("steal saved passwords from chrome", "T1555.003", "meaning"),
    ("hack a web server through a vulnerability", "T1190", "meaning"),
    ("download more malware onto the machine", "T1105", "meaning"),
]
