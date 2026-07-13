# Evaluating an AI-attack detector honestly: why accuracy lies and what we used instead

*Companion post for [Cernis](https://github.com/adamsjack711-ux/Cernis), a detector for AI-agent-driven attacks in security telemetry. Ready to publish on dev.to or GitHub Discussions.*

![PR-AUC across model variants: the hybrid clears both single models on every seed](https://raw.githubusercontent.com/adamsjack711-ux/Cernis/main/results.png)

AI agents don't attack the way people do. They move at machine speed, follow an eerily clean kill-chain order — recon, discovery, credential access, execution, lateral movement, exfiltration — and accelerate as they gain footing. Each individual action can look perfectly normal; the giveaway is the *pattern*: ordering, cadence, and how wide the activity fans out.

[Cernis](https://github.com/adamsjack711-ux/Cernis) is a small PyTorch project that learns that pattern from host logs and answers two questions per time slice: *is an AI agent behind this?* and *which MITRE ATT&CK step is it on?* But this post isn't about the model. It's about the part most portfolio ML projects skip: making sure the numbers mean something.

## Why the naive evaluation overstates everything

The default recipe — random train/test split, report accuracy — fails twice on this problem.

**Accuracy lies under imbalance.** Security telemetry is overwhelmingly benign. A detector that never fires scores 95%+ accuracy on a 95%-benign stream while catching nothing. Accuracy rewards the model for the easy majority class and hides how it behaves on the class you actually care about.

**Random splits leak.** Attack events come in campaigns — correlated bursts from one intrusion. Split windows randomly and slices of the *same campaign* land on both sides of the split. The model memorizes campaign-specific quirks in training and gets rewarded for recognizing them at test time. The score measures memory, not generalization.

Both failures inflate the number. Which is exactly why they're so common: naive evaluation makes your model look better, and nothing forces you to notice.

## What we did instead

**1. Campaign-disjoint splits.** Every split is a `GroupShuffleSplit` on `campaign_id` — a campaign lives entirely in train or entirely in test, never both. The test set is always attacks the model has genuinely never seen. This is the single change that costs the most PR-AUC and buys the most truth.

**2. PR-AUC and false alarms per hour, never accuracy.** PR-AUC measures how well the model trades precision against recall on the *minority* class, at every threshold, so the benign flood can't pad the score. And because a detector nobody trusts is a detector nobody uses, the serving loop is tuned against a false-alarms-per-hour budget rather than F1 — the threshold is picked as the most sensitive one that stays within the alert budget.

**3. Three seeds, or it didn't happen.** A single training run can flatter a model. Every headline number is re-run across seeds 0–2 and reported as mean ± std, and each claim has to hold in 3/3 runs. One lucky seed doesn't count.

There's a fourth discipline hiding underneath: the synthetic test data is built to be *hard*. Timing, depth, and AI-artifact features are drawn from the same distribution for both classes, so they carry no label signal. A fraction of attacks are deliberately low-and-slow "stealth" campaigns designed to be nearly uncatchable. That caps the achievable score on purpose — in this setup, PR-AUC ≈ 1.0 would be a red flag to investigate, not a win.

## What the honest numbers look like

The hybrid model (gradient-boosted aggregate features fused with a GRU's sequence representation) is the interesting result, because the synthetic data gives attacks two *orthogonal* signals: breadth (fan-out across targets — visible to aggregates, invisible to the GRU) and ordering (action-transition structure — visible to the GRU, invisible to aggregates). Each single model is nearly blind to the other's channel; recall on "ordering-only" attacks is 0.127 for the aggregate model, and recall on "breadth-only" attacks is 0.037 for the GRU. Across seeds 0–2, on campaign-disjoint test sets:

| model | PR-AUC (mean ± std) |
|---|---|
| aggregate-only baseline | 0.771 ± 0.033 |
| GRU-only | 0.723 ± 0.014 |
| **hybrid** | **0.927 ± 0.012** |

The hybrid beats the best single model in 3/3 seeds (mean lift +0.155). In the streaming serving loop, that translates to 96% ± 1.6 of attack traces detected at ~1.5 false alarms per hour, with a mean time-to-detect of 101.8 ± 5.5 seconds from attack onset.

## The caveat we kept

One number refused to be flattering, so it's in the README: even with per-window false positives held near one per hour, roughly half of *long benign sessions* still fire at least one alert. That's just alert-fatigue arithmetic — a long session accumulates many windows, so a small per-window rate compounds into a likely per-session alert. It's a direct consequence of building genuinely overlapping classes, and it's why a real deployment would add per-entity alert suppression on top of the FP/hour budget.

That caveat is the point of the whole exercise. An evaluation designed to make the model look good would never have surfaced it. An evaluation designed to find out the truth did — and the model still holds up.

*Code, per-seed sweeps (`sweep.py`), and the full methodology write-up: [github.com/adamsjack711-ux/Cernis](https://github.com/adamsjack711-ux/Cernis).*
