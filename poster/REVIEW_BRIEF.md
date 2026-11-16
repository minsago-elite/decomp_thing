# Final council results — 2026-11-16

| Delegate | Round 1 | Round 2 | Correction check |
| --- | --- | --- | --- |
| Opus 5.5 | 9/10 | 9/10 | 10/10 |
| GPT-6 Astra | 10/10 | 10/10 | — |
| GPT-6.1 Sol | 10/10 | 10/10 | — |

All requested fixes resolved. Final outputs: one A1 PDF and current PNG, centered header retained. No visible clipping or overflow. Final correction check changed only the Korean particle and kept 매 단계를 together.

# Council round 1 — current-state update
Opus 9/10; Astra 10/10; Sol 10/10. Opus requested A0–A5 complete and C planned. Both corrected; chart denominator and compiler wording clarified. Round 2 reviews the final rendered revision.

# Current review scope — 2026-11-16

This section supersedes all historical counts and outcomes below.
- Source synchronized to upstream e28275e3ca5b703a72f01d51601f8560d726da53 (PR #1966).
- Current required CI: https://github.com/minsago-elite/decomp_thing/actions/runs/43784036305 — success, including ten-reference-repair qualification and Kotlin lanes.
- Read docs/c-vul-qualification.md, src/main/kotlin/decompengine/mvp/MvpVulnerabilityCase.kt and MvpTenCaseWorkflowTest.kt for new boundaries.
- All ten authored reference repairs qualify. This is NOT ten real-model end-to-end reconstructions or an LLM success rate. The historical binary_01 fake-provider demo is explicitly dated 2026-11-10.
- Current milestone groups closed/open: L 14/4, A 116/301, B 29/113, C 0/60, D 96/233. Combined 255/966 issues; whole repository 265/982.
- Commits 3,682; merged PRs 828. Monthly June21, July0, August313, September1751, October1443, November154 through16th.
- Centered header and teacher 김수민 선생님 are user preferences. Keep design stable.
- Build: make -C poster all PY=/home/june/poster_forge_decomp/.venv/bin/python. Verified one A1 page, no DOM overflow.
- Review current poster/poster.html, poster/poster.pdf and poster/preview.png. Historical output paths below are context only.

---

# Council review brief — decomp_engine A1 poster

## Deliverable under review (read-only; do NOT edit any file)
- Poster HTML (single-file, renders to A1 via headless Chromium): /home/june/.t3/worktrees/decomp_thing/t3-ec047389/poster/poster.html
- Rendered PDF (1 page, A1 594x841mm): /home/june/.t3/worktrees/decomp_thing/t3-ec047389/poster/poster.pdf
- Full-page preview PNG (2245x3179): /home/june/.t3/worktrees/decomp_thing/t3-ec047389/poster/preview.png
- Zoomed crops of regions: /tmp/claude-1000/-home-june--t3-worktrees-decomp-thing-t3-ec047389/dac4da89-fd4d-4bd4-8908-38ae4af765a9/scratchpad/crops/*.png
- Screenshots used in poster: /home/june/.t3/worktrees/decomp_thing/t3-ec047389/poster/assets/spa_after_upload.png, spa_runtime_status.png
- Previous semester's poster (same author, design precedent, A1): /home/june/poster_forge/poster.html and
  /mnt/newlaptop/shared_data/home/home/june/Downloads/LLM_핑거프린팅_포스터_A1.pdf

## Grading rubric (official, Korean high-school course "인공지능 모델링", 2학기 3차 수행평가, 2026-11-24)
Image of the rubric: /home/june/.t3/worktrees/decomp_thing/t3-ec047389/poster/assets/rubric_2026-2_3rd.png
Item 1 "포스터 구성" (30 pts) — the part this poster is graded on:
  ① 프로젝트 이름, 팀명, 팀원, 과목명, 지도교사 (1 pt each, 5 total)
  ② 프로젝트 요약 (2)
  ③ 제작동기 및 필요성 (3)
  ④ 구현과정 (데이터셋, 모델, 알고리즘, 핵심코드 등) (10)
  ⑤ 산출물 결과 화면 첨부 또는 실제 산출물 배치 (5)
  ⑥ 기타 양식 준수 (A1 사이즈, 추가 도표·시각자료 활용) (5)
Item 2 "최종 작품 완성도" (30): 기획 의도와 주제 및 산출물의 유기성, 산출물의 최종 완성도·난이도
Item 3 "발표 전달력" (10), Item 4 "팀 내 기여도" (30, peer evaluation)

## Ground truth sources (verify poster claims against these)
- Project proposal (2026-09-19, Korean; NOTE: the class poster is a solo project by 박라준 — the other proposal co-authors are not in this class and must not appear on the poster):
  /mnt/newlaptop/shared_data/home/home/june/Downloads/__리버싱 도구와 결합된 LLM을 활용한 바이너리 실행 파일 취약점 탐색 및 패치(2).pdf
  (use `pdftotext -layout <file> -`). Team 민사고엘리트; authors 김주환, 박라준, 이서우, 황순건; appendix gives roles.
- Source repository checkout (read-only for you): /home/june/.t3/worktrees/decomp_thing/t3-ec047389
  Key files: README.md, src/main/kotlin/decompengine/mvp/MvpPatchWorkflow.kt, roadmap/benchmarks/vulnerability_remediation.json,
  benchmarks/fixtures/c-vul/ (10 vulnerable C examples), docs/gcc-oracle-accuracy-coverage.md, docs/gcc-function-recovery-scoring.md,
  docs/workbench-user-guide.md
- GitHub milestone counts were fetched 2026-11-10 via `gh api repos/minsago-elite/decomp_thing/milestones?state=all`
  (39 milestones; issue totals closed 262 / open 718; merged PRs 824; commits 3,667 from `git rev-list --count HEAD`;
  commits per month from `git log --format=%cd --date=format:%Y-%m | sort | uniq -c`: 06:21, 08:313, 09:1751, 10:1443, 11:139).
- Real run evidence produced 2026-11-10 on this machine with the installed build:
  - ASan output of c-vul binary_01: stack-buffer-overflow, WRITE of size 11, display_name[8] at frame offset [32,40), normalize_name line 6.
  - `llm_bin_patch reconstruct binary_01 --evidence-only`: 8 functions, 9 globals, 2 modules, Ghidra peak RSS 850,644,992 bytes, 10-min wall limit, source-tree.zip + SHA-256 manifest, UNRESOLVED.md marks entities "unassessed".
  - Web GUI (`llm_bin_patch web --ui spa`) screenshots: upload page and runtime status page.
  - The two terminal blocks in the poster are REAL outputs reproduced locally on 2026-11-10: the reconstructed C
    (VULNERABLE_SOURCE) and the patch (PATCHED_SOURCE) come verbatim from the fixture provider
    benchmarks/fixtures/mvp-c-vul/fake_openai_provider.py; ASan output is from compiling that C with
    -fsanitize=address,undefined; the patched build/hardening flags were checked with readelf (PIE, BIND_NOW).
    The poster labels these as "테스트용 응답기" (test responder) output, not LLM capability.
  - CI: .github/workflows/ci.yml runs the full `./gradlew test` suite (includes CVulFixtureIntegrationTest, the ASan
    reproduction test). scripts/validate-mvp-docker.sh (Docker end-to-end acceptance) is NOT run in CI.
  - repair --max-iterations (default 5) exists in Main.kt for the trace-guided repair workflow; MvpPatchWorkflow has no retry loop.
  - 307 MB / 90 parts = GCC driver DWARF interface evidence bundle (docs/gcc-oracle-accuracy-coverage.md ~line 327).
  - Milestone chart sums (252 closed / 713 open) differ from repo totals (262 / 718) because some issues have no milestone; the
    poster now states both.

## Round 1 (2026-11-10) results and what changed since
Scores: GPT-6 Astra 8/10, GPT-6.1 Sol 8/10, Claude Opus 5.5 8/10.
Applied: real fixture diff + ASan output with explicit "테스트용 응답기" labels; summary/results wording no longer implies LLM
capability; A0–5 and L3 marked "거의 완료"; chart retitled "주요 마일스톤", legend without 완료/계획, totals disclosed; SPA vs legacy
Workbench scope corrected; GUI captions corrected (file-selected state); core code labeled 의사코드 with "MVP는 실패 시 중단";
motivation/differentiation sentences toned down; table 2 relabeled (합성 ELF 코퍼스, GCC DWARF 증거 번들); code/terminal/refs
font sizes raised; GUI screenshots cropped to relevant regions; step numbers unified with the pipeline (①–⑦).

- Known placeholder: 지도교사 name is "○○○ 선생님" (the author must fill it in). Do not penalize the placeholder itself,
  but flag if it is not visually obvious that it must be filled.

## What we need from you
1. Score the poster out of 10 against rubric item 1 (30 pts) and item 2's "기획 의도–주제–산출물 유기성 / 완성도" as a
   poster-communication artifact. State the score explicitly as "SCORE: n/10".
2. Rubric-by-rubric check (①–⑥): is each item unmistakably present and easy for a teacher to find within 10 seconds?
3. Factual accuracy: every number, filename, claim vs the sources above. List each discrepancy with the evidence.
4. Readability at A1 (viewer at ~1 m): font sizes, contrast, overflow/clipping, chart legibility, Korean typography
   (word-break, line-breaks), consistent terminology. Inspect the PNG preview and crops; also read the HTML.
5. Honesty/claims: anything overstated (e.g., "완료" statuses, LLM capability) or anything under-sold that the rubric rewards.
6. Concrete, minimal fixes, ordered by impact. Keep scope tight: this is a poster, not a report; do not propose new sections
   unless a rubric item is missing.
Output in English or Korean, compact. Do not modify any file.
Also applied after Opus's review: event name unified (단원진로학술제 최종 발표 / 3차 수행평가); advisor placeholder visibly marked
(dashed amber, "← 인쇄 전 입력"); hero tile now "99.5% GCC 스트립 빌드 함수 경계 재현율 (3,269/3,284, precision 99.9%)" from
docs/gcc-oracle-accuracy-coverage.md ~line 58 (function-start recovery by bundled Ghidra, not source reconstruction); LLM card
states input/output; "Kotlin 1,005 파일(테스트 532 포함)"; "저장소 전체 닫힘 262 · 열림 718"; unconfirmed "c-vul 데이터셋" credit removed.

## Round 2 ask
Re-score against the same rubric. Verify that round-1 findings are resolved in the current files (re-render is already done:
poster_decomp.pdf / preview_decomp.png / crops are current). Report only remaining defects that would cost rubric points or
mislead a grader; do not propose new sections or scope. State "SCORE: n/10" first.

## Round 2 results → Round 3
Round 2: GPT-6 Astra 10/10, GPT-6.1 Sol 10/10, Claude Opus 5.5 9/10. Opus asked for: (1) the ※ note to say the terminal
blocks are "발췌·요약" of real output rather than verbatim, (2) the footer advisor placeholder to be marked too, (3) looser
screenshot crops. All three applied; subtitle now says "출력 발췌". Round 3 = confirmation of those three items only.

## Revision 2026-11-15 (after the council rounds, not re-reviewed)

Author feedback: too many middle dots, remove the team name, layout felt crammed.
- No middle dot (U+00B7) anywhere in the poster.
- Team name removed (identity card and footer). This is a solo project by 박라준.
- Two equal columns, wider card padding and line spacing, shorter copy.
- Removed: team-roles card, verification-criteria chips, Ghidra mini-stats, DWARF bundle row, English sub-labels.
- References moved to a full-width strip above the footer.
- Monospace is Comic Code.
