# ============================================================================
#  Poster build — render an HTML poster to a print-ready PDF (and PNG preview)
#  via headless Chromium (Playwright). Self-contained: the render helper is
#  generated from this Makefile, so you only need this file + the HTML + the font folders.
#
#  Usage:
#    make            # build the PDF  (default)
#    make preview    # build a PNG preview
#    make all        # PDF + preview
#    make deps       # create .venv with Playwright + Chromium
#    make fonts      # copy Comic Code from the system font dir into fonts/comic-code/
#    make watch      # rebuild on every save (needs `entr`)
#    make clean      # remove generated files
#    make help       # list targets
#
#  Override anything on the command line, e.g. switch to A0:
#    make PAGE_W=841mm PAGE_H=1189mm
#    make HTML=mydeck.html PDF=mydeck.pdf
# ============================================================================

# ---- configuration (override on the command line) --------------------------
HTML    ?= poster.html
PDF     ?= $(HTML:.html=.pdf)
PNG     ?= preview.png
# Page size — A1 by default (course requirement). B1: 707mm x 1000mm | A0: 841mm x 1189mm
PAGE_W  ?= 594mm
PAGE_H  ?= 841mm
# Uses the local virtualenv created by `make deps` when present
PY      ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
RENDER  := .render.py
FONTS   := $(wildcard fonts/comic-code/*.otf nanum-square-round/*.ttf)
# Where the licensed Comic Code OTFs are installed on this machine (not tracked in git)
CC_SRC  ?= /usr/local/share/fonts/c

.DEFAULT_GOAL := pdf
.PHONY: pdf preview all deps fonts watch open clean help

# ---- build the PDF ---------------------------------------------------------
pdf: $(PDF)

$(PDF): $(HTML) $(RENDER) $(FONTS)
	@echo ">> rendering $(HTML) -> $@  ($(strip $(PAGE_W)) x $(strip $(PAGE_H)))"
	@$(PY) $(RENDER) "$(HTML)" "$@" pdf "$(strip $(PAGE_W))" "$(strip $(PAGE_H))"

# ---- build a raster preview ------------------------------------------------
preview: $(PNG)

$(PNG): $(HTML) $(RENDER) $(FONTS)
	@echo ">> rendering preview $(HTML) -> $@"
	@$(PY) $(RENDER) "$(HTML)" "$@" png "$(strip $(PAGE_W))" "$(strip $(PAGE_H))"

all: pdf preview

# ---- generate the Playwright render helper from this Makefile --------------
$(RENDER): Makefile
	@$(file >$@,$(RENDER_PY))
	@echo ">> generated $@"

# ---- one-time environment setup --------------------------------------------
deps:
	python3 -m venv .venv
	.venv/bin/python -m pip install --quiet playwright
	.venv/bin/python -m playwright install chromium

# ---- copy the licensed Comic Code OTFs into fonts/comic-code/ (git-ignored) --
fonts:
	@mkdir -p fonts/comic-code
	@for w in Light Medium Semibold Bold; do \
		cp "$(CC_SRC)/Comic_Code_$$w.otf" fonts/comic-code/ComicCode-$$w.otf; done
	@cp "$(CC_SRC)/Comic_Code.otf" fonts/comic-code/ComicCode-Regular.otf
	@cp "$(CC_SRC)/Comic_Code_Italic.otf" fonts/comic-code/ComicCode-Italic.otf
	@echo ">> done: $$(ls fonts/comic-code | wc -l) Comic Code files (Nanum Square Round is tracked)"

# ---- live rebuild on save (requires `entr`: apt install entr) ---------------
watch:
	@echo ">> watching $(HTML) — Ctrl-C to stop"
	@ls $(HTML) | entr -r $(MAKE) pdf

# ---- open the finished PDF (Linux/macOS) -----------------------------------
open: $(PDF)
	@(xdg-open "$(PDF)" 2>/dev/null || open "$(PDF)" 2>/dev/null) &

clean:
	@rm -f $(PDF) $(PNG) $(RENDER)
	@echo ">> cleaned"

help:
	@echo "targets: pdf (default) | preview | all | deps | fonts | watch | open | clean"
	@echo "vars:    HTML=$(HTML)  PDF=$(PDF)  PAGE_W=$(PAGE_W)  PAGE_H=$(PAGE_H)"

# ---- the render helper, written verbatim to $(RENDER) ----------------------
define RENDER_PY
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

src    = Path(sys.argv[1]).resolve()
out    = Path(sys.argv[2]).resolve()
mode   = sys.argv[3] if len(sys.argv) > 3 else "pdf"
width  = sys.argv[4] if len(sys.argv) > 4 else "594mm"
height = sys.argv[5] if len(sys.argv) > 5 else "841mm"

if not src.exists():
    sys.exit(f"error: input not found: {src}")

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(src.as_uri(), wait_until="networkidle")
    page.wait_for_timeout(1200)            # let webfonts + JS charts settle
    if mode == "png":
        # ~96 dpi raster the width of the page; height auto via full_page
        px = int(float(width.rstrip("m")) / 25.4 * 96)
        page.set_viewport_size({"width": px, "height": 1400})
        page.screenshot(path=str(out), full_page=True)
    else:
        page.pdf(path=str(out), width=width, height=height,
                 print_background=True,
                 margin={"top": "0", "bottom": "0", "left": "0", "right": "0"})
    browser.close()
    if errors:
        print("page errors:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)

print(f"wrote {out}")
endef
