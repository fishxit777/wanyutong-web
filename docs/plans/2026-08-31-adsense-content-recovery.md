# AdSense Content Recovery Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the confirmed content-quality and trust risks from the WanyuTong public website before a sixth AdSense review request.

**Architecture:** Keep the existing static GitHub Pages architecture. Quarantine weak legacy pages without breaking their URLs, rebuild three pillar articles using the existing guide system, tighten two current guides, centralize testable content assertions, and deploy only after automated and visual QA pass.

**Tech Stack:** Static HTML/CSS/JavaScript, Python 3 standard-library audit script, GitHub Pages, Google Search Console.

---

### Task 1: Record the verified product truth and recovery scope

**Files:**
- Create: `docs/plans/2026-08-31-adsense-content-recovery-design.md`
- Create: `docs/plans/2026-08-31-adsense-content-recovery.md`
- Create: `docs/adsense_content_truth_20260831.md`

**Steps:**
1. Record the free quota, language count, paid-feature scope and public commands from the production Bot source.
2. Label every fact as verified, inferred or unknown.
3. Record the five quarantined URLs and five pillar articles.
4. Verify the documents contain no credentials or customer data.

### Task 2: Add a repeatable content-quality audit

**Files:**
- Create: `scripts/audit_site_content.py`

**Steps:**
1. Parse every public HTML file with the Python standard library.
2. Assert one title, canonical and H1 on every indexable page.
3. Assert quarantined pages use `noindex,follow`, contain no AdSense loader and are absent from `blog.html` and `sitemap.xml`.
4. Assert the old template CTA, unsupported speed claims and misleading mock-account badge are absent.
5. Assert the five pillar pages include an Article schema, review section, limitation language and expected first-party sources.
6. Run `python scripts/audit_site_content.py`; expected result is FAIL before content changes.

### Task 3: Quarantine five weak legacy pages

**Files:**
- Modify: `blog-caregiver-line-translation.html`
- Modify: `blog-construction-line-translation.html`
- Modify: `blog-factory-line-translation.html`
- Modify: `blog-foreign-worker-safety-law.html`
- Modify: `blog-restaurant-foreign-worker-translation.html`
- Modify: `blog.html`
- Modify: `sitemap.xml`

**Steps:**
1. Replace each weak page with a concise maintenance notice, `noindex,follow`, canonical URL, and links to current verified guides.
2. Do not load AdSense on these pages.
3. Remove their cards from `blog.html`.
4. Remove their entries from `sitemap.xml`.
5. Run the content audit; quarantine assertions must pass.

### Task 4: Rebuild the three legacy pillar articles

**Files:**
- Modify: `blog-line-group-translation.html`
- Modify: `blog-image-ocr-translation.html`
- Modify: `blog-foreign-worker-communication.html`

**Steps:**
1. Replace the duplicated bilingual template with one Traditional Chinese article per URL.
2. Use existing de-identified guide images and label them as demonstrations.
3. Add reproducible steps, realistic test examples, limitations, human-review warnings and official sources.
4. Add Article JSON-LD with `dateModified` set to `2026-08-31`.
5. Keep the AdSense loader only on the complete pillar articles.
6. Run the content audit; all pillar assertions must pass.

### Task 5: Tighten onboarding and pricing guides

**Files:**
- Modify: `blog-line-bot-first-setup.html`
- Modify: `blog-free-paid-plans.html`

**Steps:**
1. Confirm commands and quota against production `app.py`.
2. State which features require a paid group plan and that availability follows the current Bot/payment screen.
3. Add a visible review date, known limits, and safe payment guidance.
4. Remove any claim not reproducible from the public Bot.
5. Run the content audit.

### Task 6: Remove unsupported claims from shared public pages

**Files:**
- Modify: `index.html`
- Modify: `features.html`
- Modify: `pricing.html`
- Modify: `contact.html`
- Modify: `terms.html`
- Modify: `compare.html`
- Modify: `start.html`
- Modify: `industries.html`
- Modify: `engine.html`
- Modify: `join.html`

**Steps:**
1. Replace the `0.3秒` / `0.3s` stat with a non-numeric, verifiable label.
2. Replace the mock `Official` badge with a neutral WanyuTong label.
3. Preserve legitimate references to the LINE Official Account product type and WanyuTong's own official contact channels.
4. Run `rg -n -F '0.3秒' .` and `rg -n -F "'0.3s'" .`; expected no product-copy matches.
5. Run the content audit.

### Task 7: Verify structure, links and mobile rendering

**Files:**
- Modify if needed: files touched in Tasks 3-6

**Steps:**
1. Run `python scripts/audit_site_content.py`; expected PASS.
2. Start a local static server with `python -m http.server 8765`.
3. Inspect homepage, blog index, three pillar articles, pricing and one quarantine page at desktop and mobile widths.
4. Fix missing images, overflow, broken anchors, unreadable tables or navigation issues.
5. Re-run the audit after visual fixes.

### Task 8: Commit, merge and deploy

**Files:**
- Update: `README.md`
- Create: `docs/adsense_content_recovery_20260831.md`

**Steps:**
1. Record changed pages, test output and sixth-review gates in the handoff document.
2. Run final audit and `git diff --check`.
3. Commit only the recovery files; exclude unrelated user files.
4. Merge the recovery branch into `main` and push `origin/main` to trigger GitHub Pages.
5. Verify production HTTP status, canonical, robots, sitemap, ads.txt and representative page content.

### Task 9: Re-index and defer the sixth review

**Files:**
- Update: `docs/adsense_content_recovery_20260831.md`

**Steps:**
1. Submit the updated sitemap and request indexing for the homepage, blog index and pillar articles through Search Console when the authenticated session is available.
2. Record which requests were accepted and which require later verification.
3. Create a delayed monitoring task for crawl/index evidence.
4. Do not click the AdSense resubmit checkbox until the documented gates pass after the crawl window.

