# Changelog

Append-only record of who changed what. Newest first. See the attribution rules in
[`AGENTS.md`](../AGENTS.md#attribution-and-change-tracking).

Each entry gives the date, the owner, a one-line summary, then one line per file touched
with the lines added/removed for that file, and the totals for the task.

---

## 2026-09-12 - Gowtham - replace the filter selects with a custom ARIA combobox

Gowtham found that the native `<select>` from the previous entry had its own defect: in
every table the option list was clipped by the sticky table header instead of drawing over
it. Since neither off-the-shelf option worked - a native select is clipped, and Base UI's
Select is blocked by the CSP - he wrote the component.

`FilterSelect` is now a hand-built ARIA select-only combobox. The popup is portalled to
`document.body`, fixed-positioned at `z-index: 60` against the header's `2`, and positioned
through React's `style` prop, which writes via CSSOM and so is untouched by
`style-src 'self'`. Focus stays on the trigger while `aria-activedescendant` tracks the
active option, which avoids moving focus into the list at all.

Behaviour: opens on click, ArrowDown, ArrowUp, Enter or Space; ArrowUp/Down move, Home and
End jump, printable characters type-ahead within a 700 ms window, Enter or Space commits,
Escape closes, Tab closes without committing, and an outside pointer-down dismisses. Focus
returns to the trigger on close. The popup flips above the trigger when there is more room
there, is clamped to stay on screen near the right edge, repositions on scroll and resize
(capture phase, since the console scrolls `.content` rather than the window), and keeps the
active option scrolled into view.

Verified: portalled into `<body>`, `z-index` 60 over the header's 2, three positioning
properties applied rather than CSP-stripped, and `elementFromPoint` at the popup's location
returns the option itself - so it paints above the header rather than under it. Mouse
selection filters 42 rows to 12 criticals; keyboard open → Home → Enter restores all 42 and
returns focus to the trigger.

| File | Change | +/− |
|---|---|---|
| `dashboard-security/src/controls.tsx` | Rewrote `FilterSelect` as a portalled ARIA combobox with full keyboard support, flip, clamp and reposition (48 → 227 lines) | +186 / −7 |
| `dashboard-security/src/styles.css` | Replaced the native-select shell styling with trigger, popup and option styling; popup fixed at `z-index: 60` with the spring entry animation | +15 / −0 |

**Totals:** 2 files changed, +201 / −7. Bundle 376 KB minified. The `FilterSelect` API is
unchanged, so no call site moved.

---

## 2026-09-12 - Gowtham - Base UI drawer, native selects, solid table cards, chart fills its row

Gowtham adopted Base UI for the overlay components, reverted the table cards to the
original opaque surface, and fixed the row-height problem visible on both a large display
and a 13.3-inch screen at 100% zoom.

**Drawer on Base UI Dialog.** The incident drawer now uses `Dialog.Root` / `Portal` /
`Backdrop` / `Popup` / `Close`, replacing a hand-rolled Escape listener that had no focus
trap. Verified against the real CSP: Escape closes, body scroll locks and unlocks, and
focus returns to the originating table row. Base UI's own `initialFocus` is skipped for
pointer-opened dialogs in `1.0.0-rc.0` - both the ref and the function form were ignored -
so focus is placed on the Close button explicitly; without that, focus stayed outside the
panel and Tab could walk straight back out of the modal.

**Selects stayed native, and this is the important finding.** The filters were moved to
Base UI's Select and it did not work: the component positions its popup through an inline
`style` attribute, and the API serves `style-src 'self'` with no `unsafe-inline`, so the
browser blocked it - console reported *"Applying inline style violates the following
Content Security Policy directive"*, `.sel-popup` was left with an empty style attribute
and zero applied properties, and selections never committed. The filters are now a styled
shell around a native `<select>`, whose option list the browser draws itself and which is
therefore immune. Same `FilterSelect` API at every call site, so this can be swapped back
if the CSP ever changes. **Base UI Select cannot be used here without relaxing
`style-src` in `backend/sih_api/app.py`** - a backend file, and a real weakening of a
security control, so it was left alone.

**Table cards reverted.** `.card.solid` restores the original opaque `--surface` fill for
the Incidents and Entities cards; the glass gradient behind a dense grid of rows made the
rows read unevenly. The glass treatment stays on every other panel.

**Chart fills its row.** `.row-split` stretched both cards to the taller one's height,
which left a large void under whichever card was shorter - the chart card on a wide
display, the severity card at 1280. The chart is now measured with a `ResizeObserver` and
drawn at its container's true pixel size, so it takes the leftover height instead of
letterboxing, and both cards match again. Also stopped the "Critical only" button
splitting across two lines in a narrow card head.

| File | Change | +/− |
|---|---|---|
| `dashboard-security/src/styles.css` | `.card.solid` modifier; filter-select shell styling; `.card.fill` and absolutely-positioned chart SVG; `white-space: nowrap` on buttons | +149 / −0 |
| `dashboard-security/src/Charts.tsx` | `useBox` ResizeObserver; chart drawn at container pixel size; x-label density from available width; hover index clamped when the series shrinks | +38 / −17 |
| `dashboard-security/src/IncidentDetail.tsx` | Drawer rebuilt on Base UI Dialog; removed the hand-rolled Escape handler and scrim button; explicit initial focus | +9 / −0 |
| `dashboard-security/src/Dashboard.tsx` | Range filter through `FilterSelect`; `solid` on the Entities card | +4 / −1 |
| `dashboard-security/src/IncidentTable.tsx` | Filters through `FilterSelect` with capitalised labels; `solid` on the Incidents card | +24 / −22 |
| `dashboard-security/package.json` | Added `@base-ui-components/react` | +1 / −0 |

### Files added

| File | Purpose | Lines |
|---|---|---|
| `dashboard-security/src/controls.tsx` | `FilterSelect` - styled native select, with the CSP reasoning recorded in the file | 48 |

**Totals:** 6 files modified (+225 / −40), 1 file added (48 lines). Bundle 368 KB minified.

---

## 2026-09-12 - Gowtham - fix the 13-inch overview layout, add glass surfaces and spring motion

Gowtham reviewed the overview at 1280×800 (13-inch) and fixed the two things breaking that
row, then gave the panels the glass-and-gradient treatment from the reference design.

**Layout.** The severity breakdown put five tiles into a two-column grid, so the fifth -
Info - was left spanning the full width as an orphan. It is now a six-track grid: the two
urgent tiles take three tracks each on the first row, the three quieter ones take two each
on the second. Five tiles fill two rows with no gap, and tile size now encodes priority
rather than just filling space. The percentage captions are held on one line so tiles in a
row stay the same height. Separately, `.row-split` stretched both cards to the taller one's
height, leaving a large void under the shorter chart card; the row now sizes each card to
its own content.

**Colour and material.** Cards moved from a flat fill to a multi-point gradient - a corner
sheen over a four-stop diagonal. The hero card layers three light sources (amber top-left,
rose top-right, a warm lift from below) over a four-stop base. Fixed ambient blooms sit
behind the whole shell, and the sidebar, top bar, cards, tiles, tooltip and drawer are now
translucent with `backdrop-filter`, a bright top lip and a soft drop, so they read as glass
against those blooms rather than as flat dark rectangles.

**Motion.** Adopted the spring easings from kinetics.colorion.co (pure CSS, no dependency):
`--spring` for press and lift, `--ease` for colour transitions. Buttons and nav items scale
on press, severity tiles lift on hover, and the drawer, scrim and "newer updates" banner
animate in on springs. The `prefers-reduced-motion` rule was widened to silence the new
keyframes as well as transitions.

| File | Change | +/− |
|---|---|---|
| `dashboard-security/src/styles.css` | Glass tokens and spring easings; ambient blooms on the shell; multi-point gradients on cards and the hero; six-track severity grid; translucent sidebar, top bar, tiles, tooltip and drawer; spring press and hover states; widened reduced-motion rule | +91 / −0 |

**Totals:** 1 file changed, +91 / −0 (stylesheet now +753 / −59 against baseline).

Not adopted: **coss ui** and **reui** both require Tailwind CSS plus Base UI or Radix. They
would work here - Tailwind compiles to a static stylesheet, which the API's
`style-src 'self'` CSP allows - but adopting them means adding a Tailwind build step and
rewriting the components, which would discard the hand-matched reference styling. Left as a
decision for Gowtham rather than done halfway.

---

## 2026-09-12 - Gowtham - correct the entity icon map against the real alert contract

Gowtham ran the `mixed` demo scenario end to end and found that the interface had been
built against assumed entity kinds rather than the contract. The real vocabulary in
`schemas/alert.v1.schema.json` is `src_host`, `dst_host`, `dst_service`, `service_pair`
and `src_domain` - not OT device types - so **every row in the table fell back to a
question-mark icon** against live data. He remapped the icons to the five contract values
(host, target host, service endpoint, conversation, domain), humanised the kind label,
and made long entity keys truncate with the full value on hover, since `src_domain` keys
are DGA domains up to 320 characters and were forcing the row wide.

| File | Change | +/− |
|---|---|---|
| `dashboard-security/src/brand.tsx` | Replaced the invented OT-device icon map with the five entity kinds from the alert schema | +8 / −9 |
| `dashboard-security/src/IncidentTable.tsx` | Humanised the entity kind label; entity key now carries a `title` for its full value | +2 / −2 |
| `dashboard-security/src/Dashboard.tsx` | Same two fixes in the Entities view | +2 / −2 |
| `dashboard-security/src/styles.css` | Entity key truncates with ellipsis at 30ch; `.entity > div` gets `min-width: 0` so the flex child can shrink | +8 / −0 |

**Totals:** 4 files changed, +20 / −13.

Verified against real data: the `mixed` scenario produced 5,403 raw events, 116 feature
records, 52 alert updates and 50 incidents across six threat classes (dga, ddos,
beaconing, dns_tunnel, encrypted_malware_like, scan) with zero invalid events.

---

## 2026-09-12 - Gowtham - rebrand the SOC dashboard to Aegis OT and rebuild its interface

Gowtham rebranded the security dashboard from "SIH SOC" to **Aegis OT** and rebuilt its
interface to match a supplied dark reference design: a fixed sidebar with breadcrumb top
bar, 20px-radius cards on hairline borders, a single orange accent with one gradient hero
card, and a bar chart whose peak bar carries an orange-to-white gradient. He self-hosted
Plus Jakarta Sans, adopted Phosphor Icons, and split the former two-component dashboard
into a shell plus focused view components. He also set up per-author change tracking for
the repository.

He fixed four defects found while rebuilding:

- Table rows were click-only, so **keyboard users could not open an incident at all**;
  rows are now focusable and respond to Enter and Space.
- `word-break: break-all` split IP addresses mid-octet (`10.20.4.201` rendered as
  `10.20.4.20 / 1`).
- Live alerts prepended to the table continuously, shifting rows under the pointer and
  causing misclicks; updates are now buffered behind a "newer updates" control while the
  pointer rests on the table or an incident is open.
- `.grid` auto-fit left a large dead area whenever the stat-card count did not divide
  evenly across the row.

He did not touch the backend, detection, consumer, ingest or infrastructure code. He also
did not rename the `sih_*` Python packages, the container image names or the Compose
project - those remain as Sanjay Kannan built them, and renaming them is deliberately
deferred.

### Files changed

| File | Change | +/− |
|---|---|---|
| `dashboard-security/src/styles.css` | Replaced the stylesheet with an Aegis token system: four-level near-black surface stack, orange accent with hero and bar gradients, a severity ramp where brand orange doubles as `critical`, self-hosted Plus Jakarta Sans `@font-face`, and styling for the sidebar, top bar, cards, severity tiles, charts, table, drawer and login | +654 / −59 |
| `dashboard-security/src/Dashboard.tsx` | Became the app shell: sidebar/top-bar layout, four working views (Overview, Incidents, Entities, Detections), live-update buffering, ⌘K search focus, and evidence export | +287 / −114 |
| `dashboard-security/src/StatsPanel.tsx` | Rewrote as the hero stat row, severity breakdown tiles, alert-rate chart with a per-minute/per-hour toggle, threat-class and confidence cards, and a latency card | +242 / −99 |
| `dashboard-security/src/IncidentDetail.tsx` | Restyled the drawer: scrim, sticky header, Escape-to-close, one definition grid so values align across sections, and formatted evidence values | +167 / −78 |
| `dashboard-security/src/App.tsx` | Rebranded the login screen with the Aegis lockup, a submitting state, and actionable error copy | +29 / −6 |
| `dashboard-security/build.mjs` | Copies the favicon and the Plus Jakarta Sans woff2 into `dist/` alongside the bundle | +9 / −1 |
| `dashboard-security/index.html` | Title, favicon link, font preload, and `color-scheme` | +4 / −1 |
| `dashboard-security/package.json` | Added `@phosphor-icons/react` and `@fontsource-variable/plus-jakarta-sans` | +2 / −0 |
| `AGENTS.md` | Added an "Attribution and change tracking" section recording Sanjay Kannan as the baseline author, Gowtham as the current UI owner, and the rules for logging every edit | +13 / −0 |

### Files added

| File | Purpose | Lines |
|---|---|---|
| `dashboard-security/src/IncidentTable.tsx` | The incident table: severity badges, entity avatars, relative timestamps, status pills, keyboard-accessible rows | 190 |
| `dashboard-security/src/Charts.tsx` | `BarChart` with gradient peak bar and tooltip, and `HBars` for categorical distributions | 138 |
| `dashboard-security/src/Sidebar.tsx` | Brand lockup, search, section nav with counts, passive-simulation notice, user row | 113 |
| `dashboard-security/src/format.ts` | Time, byte, rate, latency and confidence formatting; unavailable values stay unavailable | 84 |
| `dashboard-security/src/TopBar.tsx` | Breadcrumb, live-stream chip, history-store warning, refresh and export | 74 |
| `dashboard-security/src/brand.tsx` | The Aegis shield mark, the brand lockup, and the entity-kind icon map | 59 |
| `dashboard-security/favicon.svg` | Browser-tab mark | 6 |
| `docs/changelog.md` | This log | 36 |

**Totals:** 9 files modified (+1,407 / −358), 8 files added (700 lines). 17 files touched.

---

## Baseline - Sanjay Kannan - full application

Sanjay Kannan built and handed over the complete system: Zeek sensor and PCAP handling,
the simulated one-way link (sender, receiver, framing), Redpanda topics, the PyFlink
detection job with bounded keyed state and local ONNX scoring, model training and export,
the ClickHouse / OpenSearch / notifier / archive consumers, the FastAPI backend, the
React SOC dashboard, the Grafana platform dashboard, data generation, Docker images,
Compose topology, operational scripts and the full documentation set.

Everything in the repository before the first dated entry above is his work.
