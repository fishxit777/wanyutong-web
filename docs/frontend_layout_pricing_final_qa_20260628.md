# WanyuTong Frontend Layout And Pricing QA

Date: 2026-06-28

## Scope

This handoff records the latest public website cleanup for WanyuTong:

- Public website pages
- Blog pages
- FAQ, terms, privacy, contact
- Join / web-app entry page
- Mobile, tablet, and desktop layouts
- Traditional Chinese / English language switch
- Dark / light mode

## Fixes Completed

1. Final pricing copy is synchronized across static HTML and runtime language dictionaries.
   - Free: $0, immediate use, unlimited Chinese/English/Japanese/Korean, other languages 50/day.
   - Monthly: NT$99 / 30 days.
   - Half-year: NT$499 / 180 days.
   - Annual: NT$799 / 420 days.
   - Premium: NT$2500, lifetime buyout per group, dedicated custom bot, planned Taiwanese and Hakka versions.

2. Removed stale campaign and referral wording from public surfaces.
   - No referral bonus.
   - No 7-day trial wording.
   - No old annual NT$899 / 365-day wording.

3. Removed the homepage bottom topic directory block.
   - The homepage now keeps only the key entry points.
   - Detailed content remains in separate theme pages through top navigation.

4. Public contact information is unified.
   - Public support email: `wanyutong29@gmail.com`.
   - Support form text: `GOOGLE 客服表單`.
   - Support form URL: `https://forms.gle/rKatiHrCmh5wpCov8`.

5. Public wording avoids customer-facing backend/admin terminology.
   - Replaced with record search, statistics, support, management, or service wording where appropriate.

6. Compare page wording updated.
   - `多語同翻` now says `目前8種 持續研發中`.

7. Logo behavior verified.
   - Top-left brand logo links to `index.html`.

8. Root favicon added.
   - Added `favicon.ico` so special verification pages do not trigger a missing favicon request.

## Verification

Automated browser QA was run with Playwright against the local static server:

- Pages checked: 22 HTML files.
- Viewports:
  - Desktop: 1440 x 1000
  - Tablet: 820 x 1180
  - Mobile: 390 x 844
- States checked per page:
  - Chinese + dark mode
  - English + dark mode
  - English + light mode

Total checks: 198.

Checks performed:

- Horizontal overflow and off-screen element scan.
- Stale public text scan.
- Pricing and old-plan wording scan.
- Private email scan.
- Removed referral / promotion scan.
- Removed topic-directory wording scan.
- Logo link check on homepage.
- Missing resource / 404 scan.

Latest result: all automated layout and stale-text checks passed.

## Manual Follow-Up

GitHub Pages may keep an old cache briefly after push. If the live site still shows old data, hard refresh or add a cache-busting query such as `?v=20260628`.

No backend, payment callback, LINE Bot reply logic, Render env vars, or database schema were changed in this frontend pass.
