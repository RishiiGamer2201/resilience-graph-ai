# LANL red-team window extract

- Lines read from auth.txt: **519,368,230** (early-exit at t>2643447)
- Rows kept: **11,221,902**
  - involving compromised users: 9,948,136
  - malicious (red-team ground truth): **702** / 715 red-team events
  - background normal sample (1-in-400): 1,273,766
- Compromised users: 104 · red-team computers: 305

Label: 1 = red-team auth (malicious), 0 = benign. Use for E1.3 lateral-
movement detection (TPR @ fixed FPR vs this ground truth).