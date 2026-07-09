# CIC-IDS2017 preprocessing report

- Raw rows read: **2,830,743** across 8 daily files
- Inf cells found (Pitfall B): **4,376** -> set to NaN
- Rows dropped (NaN): **2,867**
- Rows dropped (duplicates, Pitfall C): **530,840**
- Leakage cols dropped (Pitfall C): ['Destination Port']
- **Final rows: 2,297,036** · features: 77

## Class balance (Pitfall A — imbalance is expected)
- BENIGN: **1,960,544 (85.4%)**  ·  ATTACK: **336,492 (14.6%)**
- ⚠️ Do NOT report accuracy downstream. Use PR-AUC / F1 / recall.
- Engine 1 trains on BENIGN-only (unsupervised) → imbalance does not bias training; SMOTE N/A.

## Attack-type distribution
- BENIGN: 1,960,544
- DoS Hulk: 172,846
- DDoS: 128,014
- DoS GoldenEye: 10,286
- FTP-Patator: 5,931
- DoS slowloris: 5,385
- DoS Slowhttptest: 5,228
- SSH-Patator: 3,219
- PortScan: 1,956
- Web Attack � Brute Force: 1,470
- Bot: 1,437
- Web Attack � XSS: 652
- Infiltration: 36
- Web Attack � Sql Injection: 21
- Heartbleed: 11

## Rows per day (use `day` col for train/test split, not random shuffle)
- Friday: 225,745
- Friday: 286,467
- Friday: 191,033
- Monday: 529,918
- Thursday: 288,602
- Thursday: 170,366
- Tuesday: 445,909
- Wednesday: 692,703