# Cyber-Crime-Assignment-1-Group-25
ISEC3004 Assignment 1 - vulnerability analysis, exploitation, detection, and mitigation for Path Traversal and Web Cache Poisoning.

This repository contains a deliberately vulnerable implementation, exploitation scripts, detection/tracing tooling, and security-enhanced (mitigated) code for two selected vulnerabilities:

1. Path Traversal (Path Resolution Vulnerability) - CWE-22
2. Web Cache Poisoning

For each vulnerability, this repo demonstrates the full pipeline: vulnerable code → exploitation → detection & tracing → mitigation → verification.

## Folder Structure

Cyber-Crime-Assignment-1-Group-25/
├── Path Traversal/
│   ├── Detection/
│   │   ├── evidence/
│   │   ├── pt_detector.py
│   │   └── README.md
│   ├── app_files/
│   │   └── welcome.txt
│   ├── exploit.py
│   ├── mitigated_app.py
│   ├── secret_config.txt
│   ├── vulnerable_app.py
│   └── README.md
├── Web Cache Poisoning/
│   ├── Detection/
│   │   ├── evidence/
│   │   │   └── wcp_vulnerable.log
│   │   ├── instrumented_run.py
│   │   ├── wcp_detector.py
│   │   └── README.md
│   ├── exploit/
│   │   └── exploit.py
│   ├── mitigated/
│   │   └── app_mitigated.py
│   ├── Vulnerable/
│   │   └── vulnerable_app.py
│   └── README.md
├── evidence/                    
│   ├── kanban/                  # GitHub Projects board screenshots
│   ├── toggl/                   # Meeting Reports
│   └── github/                  # Commit history screenshots
├── .gitignore
└── README.md