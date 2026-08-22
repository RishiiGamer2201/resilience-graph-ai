# Logistic-regression baseline

Dataset: LANL auth red-team window · 3,366,571 held-out rows · attack prevalence 0.0063% · stratified 70/30, random_state=42
Features: `is_fail, new_dst_for_user, new_src_for_user, user_distinct_dst_sofar, user_fail_rate_sofar, dst_rarity, is_ntlm`

| Metric | Logistic regression (supervised) | Autoencoder (unsupervised, shipped) |
|---|---|---|
| ROC-AUC | 0.9974 | 0.9929 |
| PR-AUC | 0.0878 | 0.0088 |
| TPR @ 1% FPR | 0.9194 | 0.9005 |
| F1 @ 0.5 | 0.004 | n/a (no threshold semantics) |
| Precision @ 0.5 | 0.002 | n/a |
| Recall @ 0.5 | 1.0 | n/a |
| FPR @ 0.5 | 0.0315 | n/a |

## Verdict

**Logistic regression wins on ranking here, and it is published because it is the result.** It reaches a higher TPR at the 1% false-positive point and a much higher PR-AUC. Three things qualify that, none of which erase it:

1. **LR is trained WITH the red-team labels.** The autoencoder never sees one. For a novel campaign there are no labels to train on, which is the whole reason the unsupervised detector is the one that ships.
2. **This is a stratified random split, not the protocol behind our headline number.** Events from the same campaign land on both sides of it, which flatters a supervised model far more than an unsupervised one. The 87.7% TPR reported elsewhere comes from the documented protocol in `reports/lanl_redteam_detection.md`; the two numbers are not interchangeable and should not be compared directly.
3. **At a usable threshold LR is not usable.** F1 0.004 with a 3.1% false-positive rate. It ranks well and cannot be operated.

The honest reading: on labelled data from a campaign you have already seen, a linear model is a strong ranker. That is not the problem this detector exists to solve, and the comparison belongs on the record either way.

Logistic regression is trained WITH the red-team labels; the autoencoder never sees one. A supervised linear model is the fair, hard baseline for an unsupervised detector on identical features, which is why it is worth publishing whichever way it lands.

F1, precision and recall are reported at the 0.5 decision threshold for the supervised model only. The autoencoder has no such threshold — it is calibrated to a false-positive rate — which is why TPR at a fixed FPR is the row that actually compares the two.
