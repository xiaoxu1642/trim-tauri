# AGENTS.md — Trim (Tauri) Agent Collaboration Constraints (tracked in-repo since 2026-10-24)

> This file holds only three things: **behavior discipline, non-negotiable red lines, and where to look**.
> Long-term maintenance details live in the Obsidian vault folder `trim-tauri/` (vault library `ob doucument`, a local knowledge base — paths below it are vault-relative, not repository-relative):
> - Current long-line maintenance: `trim-tauri 08 当前 AGENTS 长线维护 2026-10-24.md`
> - Review methodology: `本仓库审查规范\本仓库审查方法论.md`
> - Release manual / dependency list / red-line counterexamples / test components: `本仓库其他规范流程\`
>
> When this file conflicts with a vault long-line document, the stricter safety rule wins. This file never copies long prose — two copies rot.

## 1. Think Before Coding
**Do not assume, do not hide doubts, lay out the trade-offs first.**

- List the to-dos before starting; for multi-step work write "step → verification" before touching anything.
- State the baseline triplet first: `git rev-parse --short HEAD` / `git status --porcelain` / `git diff --cached --stat`. Every review or fix conclusion must say whether it holds on the working tree, the index, or a clean clone.
- Query order before starting: repository knowledge / architecture / past decisions → **vault-cortex**; baseline / symbols / call graph / blast radius → **srclight**; only if both miss, read source or grep.
- Ask when ambiguous — never silently pick one reading; say it outright when a simpler approach exists; when the user message is already an explicit checklist, execute it item by item and report item by item.
- If unfinished work remains and the user asks for a release: **remind them of the unfinished items first** (see §7).

## 2. Simplicity First
**Solve with the least code; no speculative design.**

- Zero frontend frameworks, no new npm dependencies; any new Rust dependency or feature must be registered in the vault `本仓库其他规范流程\依赖清单.md`.
- No abstraction for one-off code; no unrequested "flexibility / configurability"; no fallbacks for scenarios that cannot happen.
- Do not widen scope: fixing a bug does not license refactoring neighbors; unrelated dead code is reported, not deleted.
- UI uses only existing tokens from `src/styles/main.css`; corner radii limited to small 6 / btn 8 / medium 10 / large 14 (pills and badges excepted); no colored gradients and no decorative ambient glow; no animation under `prefers-reduced-motion` (the one-shot splash entrance excepted).
- Copy carries no parenthetical explanations and no technical self-justification; the number of tiers/options is set by what the user can actually tell apart.
- The single source of truth for frontend escaping and byte formatting is `src/scripts/ds.js` (`ds.esc` / `ds.escAttr` / `ds.fmtBytes`); local reimplementations are forbidden; `src/*.html` files carry no inline script.
- Before adding an interaction, check whether `ds` already has a piece; do not add design-system components unless the existing ones genuinely cannot express it.

## 3. Surgical Changes
**Touch only what must change; clean up only orphans you created.**

- Change only the named scope; never roll back others' existing uncommitted work; no unrelated formatting.
- Edit files with Edit/Write, never shell string replacement (CRLF and backticks silently corrupt files).
- Comments explain "why / constraint / root cause", not "what this line does"; no hardcoded numbers; when referring elsewhere give coordinates; never write absolute paths outside the repo.
- Deliberate designs are preserved and must never be "optimized" away: main window minimum size, the black-flash handshake (main window shows after `app:first-paint`; each subwindow uses its own `on_page_load(Finished)`), the pure-black backdrop for image comparison (LiteBox embedded in the main window), no native material operations on maximize/restore, and fully opaque `body.win-maximized` / `data-material="none"`.
- High-risk confirmation dialogs put the default focus on the **primary button** (user ruling 2026-10-03, sole source of truth `update.md`); the guardrail is a red button + "仍然执行" wording + structured warning + Esc / overlay / cancel.
- Status bars and counters count the **net change set**, not the number of actions; a changed notice bar and the fully-undone state must be equal height or keep a placeholder — never squeeze the list below.
- A new `#[tauri::command]` requires syncing: `generate_handler!` in `lib.rs`, `CHANNEL_MAP` in `src/scripts/tauri-api.js`, and `MUST_MAIN` / `MUST_READONLY` in `tools/check-guard-tiers.mjs`. A new subwindow label requires syncing: `engine::guard::APP_WINDOWS`, `capabilities/subwindows.json`, the window creation site's `with_browser_args`, and the `src/*.html` page.
- Never expose raw command-callable handles on `window`; main-window-only high-risk channels such as `elevate_request` must not be delegated downward.
- After moving a file, sync the bundle manifest in `tauri.conf.json` and every reference; icons go under `src/assets/ico/`.
- Data/rule-library changes go through the generator and re-signing; generated artifacts are never hand-edited.

## 4. Goal-Driven Execution
**Define the success criterion first, then loop until verification passes.**

- Multi-step work starts with a checklist, each step carrying its verification method; update the status as items complete.
- Acceptance commands (choose by change surface; the mandatory gate list is computed live by `node tools/check-gate-roster.mjs`):

```powershell
cd src-tauri; cargo check --all-targets; cargo test; cd ..
node tools/check-gate-roster.mjs --run
node --check <每个改动的 .js>
```

### 4.1 Anti-False-Green Guard and Positive Controls
- **Anti-false-green**: every new assertion must be able to turn red (break it once on purpose, confirm the exit code is non-zero, then restore); an assertion that only prints ✓ does not count as acceptance; the assertion must name "what was achieved"; SKIP does not count as passing; the `Finished` line of `cargo check` is not evidence of fresh artifacts; before a release, a real release build and the `#[ignore]` cases must actually run.
- **Rendering changes must be seen on a real machine**, in the order **CDP → Computer Use → honestly mark as unverified**; default port 9222, auto-enabled in dev builds and off in production builds, and changing the port requires a restart; when CDP cannot reach it (OS drag, native dialogs, real pointer hover) switch to Computer Use; when neither can reach it, mark it unverified — never substitute "looks right" for a conclusion.

### 4.2 MockRuntime Windowless Verification
- Single source of truth for helpers: `src-tauri/tests/common/mod.rs`; new module verification lands in `module_smoke.rs` and does not touch the regression net; the fast group uses only zero-side-effect commands, while touching disk / outbound calls / system changes go into `#[ignore]`.

### 4.3 Non-Negotiable Safety Red Lines
(details in the vault long-line maintenance note and `trim-tauri 02`)
- Three-layer IPC: `capabilities/*.json` + the command body's `guard` / `guard_readonly` + `CHANNEL_MAP`; `capabilities` is not a command-level gate.
- Deletion always prefers the recycle bin and must pass `engine::protect::is_path_protected` first; there is no permanent-delete fallback. Sole exception: the regular cleanup chain `cleanup_execute` is fixed to permanent delete per the v3.3.0 ruling — re-confirm with the user before changing that.
- Every PowerShell execution goes through the single entry `pwsh::run_inbox_script`; each production call site is registered in `tools/check-ps-callsites.mjs`, and the registered timeout argument must match the source.
- Write JSON through `security::atomic_write_json`; quarantine a corrupted config with `quarantine_file` first; secrets never return to the render layer in plaintext (`SECRET_MASK`); a DPAPI failure refuses to save; logs never carry sensitive data.
- The single source of truth for CSP is the meta tag in `index.html`, and `csp` in `tauri.conf.json` stays null; subwindows follow.
- Updater signature verification lives in `download()`; `requireSignedVersion` must be true; an empty `pubkey` fails closed.
- Temporary scripts are written only into the app-private tmp, never the globally writable `%TEMP%`; the elevation entry `elevate:request` accepts only the main window label.
- Rule-library field tables / limits / tokens / versions / crossTrack have the single source of truth `tools/rule-schema.json`; changing the rule library requires re-signing (`sign-cleanup-rules.mjs`); `optimizer-runtime.json` is signed via the sidecar; the inline `_sig` in the two panel side tables is likewise a mandatory re-sign surface.
- The uninstall wait chain must never force-kill the uninstaller; timeouts are reported truthfully (`exit_code: Option<u32>`).
- Snapshot slots must carry a domain (`snapshot::domain_key(label, domain)`); accounting keys use a normalized stable key (`stableItemKey`), and DOM routing keys are computed separately.
- For every read-modify-write, ask "who else might write this concurrently"; a self-built ledger inside a domain needs its own lock.
- Long-line details (31 traps, data directory, retention caps, cache hygiene, release entry points) live in the vault long-line maintenance note — never copy them here.

## 5. Contribution Hygiene
**No duplicated work, no trivial commits, no unreviewed agent output shipped as-is.**

- UI copy, source comments, and commit messages are always in Chinese; naming follows the repo's existing style.
- **Language**: the thinking chain may be in English; **all user-facing output must be concise Simplified Chinese**; when the task is done, output exactly: `小小旭已经为你完成任务了!!!`
- Never commit `docs/`, private keys, key directories, or any path outside the repo; tracked files must not reference untracked or out-of-repo paths (test: after moving to another machine and doing a clean clone, does this sentence / this line of code still hold?).
- A gate reading an untracked file must call `existsSync` first: a missing file yields an explicit SKIP that declares "this section was not verified" — no ENOENT crash and no ✓ either; tests must not depend on files or directories that exist only on this machine — when the sample is missing, `skip` with an explanation instead of letting `expect` explode (`TRIM_DPAPI_SAMPLE` is the one deliberate fail-loud case).
- Releases, pushes, PR creation, and remote changes require an explicit user instruction; never `git push`, release, or delete release assets on your own; never force push main.
- Cache hygiene: no routine `cargo clean`; when `src-tauri/target/*/incremental` exceeds 5GB, wipe the whole `incremental/`; only wipe `native-scanner/target` when it exceeds 2GB; after a release, delete the whole debug profile of `src-tauri/target` and leave `release/` alone; `docs/` and `build-release/` are never treated as cache.
- Data directory: `%APPDATA%\com.xiaoxu.trim\` (portable mode: `data/` next to the exe); never hand-edit files produced by generators or exports; retention caps and the "trim only new roots" rule live in the vault long-line maintenance note.
- Reports never claim "已验证 / 大幅提升 / 焕然一新"; report what was actually done, and always include three things: how it was verified, what the coverage was, and what gaps remain; numbers are computed on the spot, never copied from old documents or memory.

## 6. Review and Domain Guides
**Knowledge base first, then source code; the vault is authoritative for domain guides.**

- Query order: see §1 — vault-cortex → srclight → source / grep.
- Where the long-line maintenance lives: repository map, process model, 31 traps, data directory, cache hygiene, multi-agent orchestration → vault `trim-tauri 08 当前 AGENTS 长线维护 2026-10-24.md`; review methodology (two waves of two teams, receiving ledger, progress broadcast, main-agent four-sided check) → vault `本仓库审查规范\本仓库审查方法论.md`; release manual, dependency list, red-line counterexamples, test components, dual-line push → vault `本仓库其他规范流程\`.
- **Review orchestration**: follow the vault methodology "two waves, two teams" — 4–5 subagents per team, 8–10 per wave, and the next wave opens only after the previous wave's two teams are received and accepted; the main agent must maintain `_收件台账.md`, broadcast progress as `<X>/<T>`, re-dispatch missing pieces, and never let a whole wave go silent; the main agent personally owns M1 R6a, the ten M2 X0 items, M3 fix-criteria re-check, and the M4 change self-review.
- **Subagent discipline**: review only your own unit; do not conclude across units; do not read same-wave peers' split reports; do not modify source files; do not launch the app; do not run `cargo test/check`, `#[ignore]`, `check-ps-extraction`, or `check-ps-substitution`; write the report to disk and reply in chat with at most 25 lines; probes go only into your own isolated directory.
- When a domain guide conflicts with this file, the stricter safety rule wins; when a guide is stale, fix the guide instead of working around it.
- **Closing sync**: once a full task has nothing left pending, update the code index with **srclight** and the notes with **vault-cortex**; if work is still pending but the user asks for a release, **remind them first** and then follow §7; the closing sync still updates the index and notes, but "index/notes updated" must never be presented as "task complete".

## 7. Pre-PR Review Gate and Release Gate
**No diff ships unreviewed; no release without an explicit instruction.**

- Before push / PR: check related issues, open PRs, and recent changes for duplication — explain the duplication first and do not open a duplicate PR; do not open a PR for a one-off typo, pure formatting, or cleanup with no substance; the submitter must be able to explain every changed line, and the PR description must state AI involvement, the duplication check, and the test commands with results.
- **Before a release**:
  1. Check the task list: if work is still pending → **remind the user first** and wait for the call; do not enter the release flow directly.
  2. Read the vault `本仓库其他规范流程\本机发版手册.md` and follow it; sync the version in four places (`tauri.conf.json` / `Cargo.toml` / `Cargo.lock` / `readme.md`) and run `node tools/check-version-sync.mjs`.
  3. Re-sign the rule library / optimizer catalog / panel side tables by their own procedures and run `check-data-signatures`; prove artifact freshness with a real release build and the `#[ignore]` cases, not with the `Finished` line of `cargo check`.
  4. Never force push main; never delete online release assets; cross-check the packaging manifest against the assets in both directions; private keys never enter the repo.
  5. After the release: delete the debug profile of `src-tauri/target`, update `update.md` / the release record, then run the srclight index and the vault-cortex note update.
- **Closing sync**: once a full task or a release completes, run `srclight reindex` + the vault-cortex note update; if work is still pending but the user asks for a release, remind them and wait for the call — the closing sync still updates the index and notes, but "index/notes updated" must never be presented as "task complete".

---

## Legacy Section Anchors (kept for source-comment compatibility — do not delete)

> After the seven-part rewrite, source comments still cite the old numbering. The anchors below are compatibility only — no content is copied. The corresponding long-line material lives in the vault `trim-tauri 08 当前 AGENTS 长线维护 2026-10-24.md`, `本仓库其他规范流程/本机发版手册.md`, and `本仓库其他规范流程/红线依据-竞品反例.md`.

- Repository map: §0.1、§0.2、§0.3
- Workflow: §1、§1.1、§1.2、§1.3、§1.4、§1.5、§1.6、§1.7
- Hard red lines: §2
- Security model: §3
- Acceptance and anti-false-green: §4.1、§4.2
- Repo traps: §5.1、§5.2、§5.3、§5.4、§5.5、§5.6、§5.7、§5.8、§5.9、§5.10、§5.11、§5.12、§5.13、§5.14、§5.15、§5.16、§5.17、§5.18、§5.19、§5.20、§5.21、§5.22、§5.23、§5.24、§5.25、§5.26、§5.27、§5.28、§5.29、§5.30、§5.31
- Data directory: §6
- Release: §7.1、§7.2、§7.3、§7.4、§7.5、§7.6
- Cache hygiene: §8
- Naming and reporting: §9.1、§9.2、§9.3
- Multi-agent review: §10

**The sign that these rules are working**: unrelated changes in the diff shrink, rework shrinks, and ambiguities get asked about before the work starts instead of after it breaks.
