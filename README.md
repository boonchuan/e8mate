# JFSR Revision — Execution Plan

Three patches to apply to your existing `~/lib_cross_venue/` pipeline, in order.
Minimum-diff; does not touch the files that produced the FRO submission.

Working directory: `~/` (where `fetch_cross_venue.py` and `compute_metrics.py` live)

---

## Prep

```bash
# Use system python3 — venv is empty. No activation needed.
cd ~
export DATABENTO_API_KEY="db-..."   # your actual key

# Drop these three files in ~/
ls patch_1_dates.sh compute_spread_decomp.py build_jfsr_tables.py
```

---

## Patch 1 — Add pre-period dates to fetch script

```bash
chmod +x patch_1_dates.sh
./patch_1_dates.sh
```

This adds March 25–28 to the `DATES` list in `fetch_cross_venue.py`. Idempotent. Creates a `.bak` backup.

Then estimate cost and pull:

```bash
python3 fetch_cross_venue.py --estimate       # see incremental cost
python3 fetch_cross_venue.py --run --resume   # --resume skips April 1/4/7 you already have
```

**Expected:** 400 new slices (5 venues × 4 dates × 20 stocks). Roughly equal to one of your prior event-window pulls in size; budget similar cost.

---

## Patch 2 — Add spread decomposition

After the pre-period data is in place:

```bash
python3 compute_spread_decomp.py               # all venues, all dates
```

**Subset option if you want to smoke-test first:**

```bash
python3 compute_spread_decomp.py --venues XNAS --stocks AAPL MSFT --dates 2025-04-04
```

**Runtime:** Most expensive step in the pipeline. Reconstructs top-of-book from MBO for every slice. Expect ~10–30 seconds per XNAS slice, faster on secondary venues. Total for full 7-date × 4-venue × 20-stock panel: **~2-4 hours**. Resume-capable; incremental save every 20 slices.

**If you're short on time:** Run only XNAS and ARCX (the primary venues with meaningful spreads anyway):

```bash
python3 compute_spread_decomp.py --venues XNAS ARCX --resume
```

That cuts runtime roughly in half and captures 95% of the manuscript value. XPSX and XBOS have so few trades per window that their spread numbers are noisy anyway.

**Output:** `~/lib_cross_venue/spread_metrics.csv`

---

## Patch 3 — Build JFSR tables & figures

```bash
python3 build_jfsr_tables.py
```

**Runtime:** Under a minute. Produces `~/lib_cross_venue/output_jfsr/`:

- `jfsr_table1_summary.csv` — sample summary
- `jfsr_table2_microstructure.csv` — core metrics by period × venue
- `jfsr_table3_spread_decomp.csv` — spread decomposition
- `jfsr_table4_regression.csv` — cross-sectional OLS with HC3 SE
- `jfsr_table5_did.csv` — DiD venue × post interactions with clustered SE
- `jfsr_table6_placebo.csv` — Mar 25 vs Mar 28 placebo
- `jfsr_figure1_mechanism.pdf` + `.png`
- `jfsr_figure2_distribution.pdf` + `.png`
- `jfsr_main_findings.md` — headline numbers to paste into the manuscript

---

## What to send back

When everything's run, paste me the contents of:

```bash
cat ~/lib_cross_venue/output_jfsr/jfsr_main_findings.md
cat ~/lib_cross_venue/output_jfsr/jfsr_table2_microstructure.csv
cat ~/lib_cross_venue/output_jfsr/jfsr_table3_spread_decomp.csv
cat ~/lib_cross_venue/output_jfsr/jfsr_table4_regression.csv
cat ~/lib_cross_venue/output_jfsr/jfsr_table5_did.csv
cat ~/lib_cross_venue/output_jfsr/jfsr_table6_placebo.csv
```

And scp the two figure PDFs:

```bash
scp ~/lib_cross_venue/output_jfsr/jfsr_figure*.pdf YOUR_LOCAL_MACHINE:
```

I'll plug everything into the manuscript scaffold and produce the submission-ready JFSR docx with cross-venue identification as the main identification story.

---

## Checkpoints

After patch 1: `ls ~/lib_cross_venue/raw/XNAS/2025-03-25/ | wc -l` should return 20.

After patch 2: `wc -l ~/lib_cross_venue/spread_metrics.csv` should be ~560 (140 per venue × 4 venues) or ~280 if you ran only XNAS+ARCX.

After patch 3: `ls ~/lib_cross_venue/output_jfsr/` should show all 8 output files.

---

## If things go sideways

- **MBO reconstruction fails on a venue:** XBOS and XPSX have very sparse books. If spread numbers come out as NaN for those venues, it's because there were no valid TOB moments. That's fine; just drop those rows.
- **Databento API rate-limits:** `fetch_cross_venue.py` already has `--resume`. Just re-run.
- **Memory blows up on large files:** The large XNAS files (>2GB parquet) can exceed RAM during TOB reconstruction. If so, `--stocks` flag lets you process one stock at a time: `for s in AAPL MSFT NVDA; do python3 compute_spread_decomp.py --stocks $s --resume; done`.
