# poster_forge_decomp

A1 poster (594 × 841 mm) for 인공지능 모델링 2학기 3차 수행평가, 단원진로학술제 최종 발표 (2026-11-24).

Topic: **리버싱 도구와 결합된 LLM을 활용한 바이너리 실행 파일 취약점 탐색 및 패치** (decomp_engine / `llm_bin_patch`).

| File | Purpose |
| --- | --- |
| `poster.html` | Single-file poster source (HTML + CSS + inline SVG charts) |
| `poster.pdf` | Print-ready A1 PDF, one page |
| `preview.png` | Raster preview |
| `assets/` | GUI screenshots used in section 03, plus the course rubric |
| `REVIEW_BRIEF.md` | Rubric, ground-truth numbers, and council review history |

## Build

```sh
make deps    # once: .venv with Playwright + Chromium
make fonts   # once: copy Comic Code into fonts/comic-code/ (git-ignored)
make all     # poster.pdf + preview.png
```

## Fonts

- **Nanum Square Round** (SIL OFL) for Korean and body text, tracked in `nanum-square-round/`.
- **Comic Code** for monospace text. It is a licensed font, so the OTF files are not committed.
  `make fonts` copies them from `CC_SRC` (default `/usr/local/share/fonts/c`).
  If the folder is missing, the poster falls back to a system-installed Comic Code.

## Before printing

- Teacher: 김수민 선생님. Centered header retained from the previous poster.
- Updated 2026-11-16 against upstream e28275e3c. Ten authored reference repairs pass required CI; actual LLM performance remains unmeasured.
- Historical terminal output and GUI screenshots are dated 2026-11-10.
