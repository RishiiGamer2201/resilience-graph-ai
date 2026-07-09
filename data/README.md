# Data Folder Guide

Use this folder for PS7 datasets.

> **📦 Fastest way to get all data:** download the team bundle from Kaggle —
> **[ET HACK DATASET](https://kaggle.com/datasets/c3c7d72d2098d35857c2136a6d1c35785b7ba94e0f48ed6de68d0ab1ed021945)**
> (all four datasets in one place; requires a free Kaggle login). Unzip and place the contents into `data/raw/`
> following the folder layout below. The per-source instructions further down are the fallback / attribution.

## Where to put downloads

Put original downloaded files in `data/raw/...`.

Do not edit raw files directly. Any cleaned, sampled, merged, or model-ready file should go in `data/processed/...`.

## Folder layout

```text
data/
  raw/
    cicids2017/      Original CIC-IDS2017 downloads
    lanl/            Original LANL cyber event downloads
    mitre_attack/    Original MITRE ATT&CK JSON/STIX files
    unsw_nb15/       Original UNSW-NB15 downloads
  processed/
    cicids2017/      Cleaned/sampled CIC-IDS2017 files
    lanl/            Cleaned/sampled LANL files
    mitre_attack/    Parsed ATT&CK tactic/technique lookup files
    unsw_nb15/       Cleaned/sampled UNSW-NB15 files
  demo/              Small synthetic red-team scenario files for dashboard demo
```

## Download checklist

### 1. CIC-IDS2017

Download from:

https://www.unb.ca/cic/datasets/ids-2017.html

Put here:

```text
data/raw/cicids2017/
```

Download first:

```text
MachineLearningCSV.zip
```

Why:

This is our main intrusion/anomaly detection dataset. It gives labeled network-flow CSVs for benign traffic and attacks.

### 2. MITRE ATT&CK

Download from:

https://github.com/mitre-attack/attack-stix-data

Put here:

```text
data/raw/mitre_attack/
```

Download first:

```text
enterprise-attack/enterprise-attack.json
```

Optional:

```text
ics-attack/ics-attack.json
```

Why:

This gives the official tactic and technique knowledge base for ATT&CK mapping.

### 3. LANL Cyber Dataset

Download from:

https://csr.lanl.gov/data/cyber1/

Put here:

```text
data/raw/lanl/
```

Download first:

```text
redteam.txt.gz
auth.txt.gz
```

Optional later:

```text
dns.txt.gz
flows.txt.gz
proc.txt.gz
```

Why:

This supports red-team ground truth, user-host behavior, lateral movement analysis, and attack path graphs.

### 4. UNSW-NB15

Download from:

https://research.unsw.edu.au/projects/unsw-nb15-dataset

Put here:

```text
data/raw/unsw_nb15/
```

Download first:

```text
UNSW_NB15_training-set.csv
UNSW_NB15_testing-set.csv
UNSW-NB15_features.csv
```

Why:

This is an optional second benchmark to validate the intrusion detector beyond CIC-IDS2017.

## Recommended first move

Start with:

```text
data/raw/cicids2017/MachineLearningCSV.zip
data/raw/mitre_attack/enterprise-attack.json
data/raw/lanl/redteam.txt.gz
data/raw/lanl/auth.txt.gz
```

Then we can build the first version of the pipeline.
