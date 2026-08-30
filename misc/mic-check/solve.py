#!/usr/bin/env python3
"""
Mic Check -- ASIS CTF Quals 2026 (misc / warm-up)

Five "LED readouts" are drawn as three-row ASCII art. Each readout is a run of
seven-segment glyphs; each glyph is one leetspeak character. Joining the five
decoded blocks with '_' inside ASIS{} gives the flag.

Two properties of the published art drive the design of this decoder:

  * The glyphs are PROPORTIONALLY spaced. '1' is one column wide, 't' is drawn
    with a crossbar ('_|_'), everything else sits in a 3x3 cell. There is no
    fixed character pitch to slice on.

  * The TOP-SEGMENT ROW drifts. In blocks 2, 3 and 4 the top underscores sit
    one or two columns away from the glyph they belong to -- in block 4 the
    drift is large enough to visually merge two glyphs. The two lower rows are
    pixel-accurate.

So the decoder never trusts the exact column of a top segment:

  1. tile()      -- exhaustively tile the two lower rows with glyph cells,
                    keeping only tilings that consume every inked column.
  2. top count   -- a glyph's top segment is an unknown, but the NUMBER of
                    underscores in the top row is drift-independent. Only
                    three glyph pairs differ solely by the top segment
                    (4/9, l/c, u/0), so this is a small search.
  3. dictionary  -- de-leet each candidate (4->a, 3->e, 1->i, 0->o) and keep
                    the reading that is an English word.

Usage:  python3 solve.py [challenge.txt] [-v]
"""

from itertools import product
from pathlib import Path
import sys

# ---------------------------------------------------------------------------
# The font.  Segment layout of a cell:
#
#      _     <- a  (top row)
#     |_|    <- f g b   (middle row)
#     |_|    <- e d c   (bottom row)
#
# Value = (number of underscores the glyph puts in the top row, middle, bottom).
# Characters are spelled the way they appear in the flag, so 'a' is '4'.
# ---------------------------------------------------------------------------
GLYPHS = {
    "0": (1, "| |", "|_|"),
    "1": (0, "|  ", "|  "),
    "3": (1, " _|", " _|"),
    "4": (0, "|_|", "  |"),
    "9": (1, "|_|", "  |"),
    "s": (1, "|_ ", " _|"),
    "c": (1, "|  ", "|_ "),
    "f": (1, "|_ ", "|  "),
    "h": (0, "|_|", "| |"),
    "l": (0, "|  ", "|_ "),
    "n": (1, "| |", "| |"),
    "r": (1, "|_|", "|\\ "),
    "t": (2, " | ", " | "),   # crossbar: '_|_' across the whole top row
    "u": (0, "| |", "|_|"),
    "w": (0, "| |", "|/|"),
    "!": (0, "|  ", ".  "),
}

# Glyphs sharing the same two lower rows differ only by the top segment.
TWINS = {}
for _ch, (_t, _m, _b) in GLYPHS.items():
    TWINS.setdefault((_m, _b), []).append(_ch)

LEET = {"4": "a", "3": "e", "1": "i", "0": "o", "9": "g", "5": "s"}


def deleet(text):
    return "".join(LEET.get(ch, ch) for ch in text)


# ---------------------------------------------------------------------------
# 1. Tile the two lower rows.
# ---------------------------------------------------------------------------
def tile(mid, bot):
    """Every way to cover the inked columns of the lower rows with glyph cells.

    Yields lists of (left_column, character). A cell is 3 columns wide but only
    its inked columns are claimed, so a 1-column glyph such as '1' may be
    followed by a neighbour whose cell overlaps its blank columns.
    """
    width = max(len(mid), len(bot))
    mid, bot = mid.ljust(width), bot.ljust(width)
    ink = {c for c in range(width) if mid[c] != " " or bot[c] != " "}

    def walk(start, claimed):
        pending = sorted(c for c in ink if c >= start)
        if not pending:
            if claimed == ink:          # every stroke accounted for
                yield []
            return
        col = pending[0]
        for left in range(max(0, col - 2), col + 1):
            for ch, (_, m, b) in GLYPHS.items():
                cells, ok = set(), True
                for row, pattern in ((mid, m), (bot, b)):
                    for i, want in enumerate(pattern):
                        if want == " ":
                            continue
                        c = left + i
                        if c >= width or row[c] != want:
                            ok = False
                            break
                        cells.add(c)
                    if not ok:
                        break
                # The glyph must start exactly at the first unclaimed stroke.
                if not ok or min(cells) != col:
                    continue
                for rest in walk(max(cells) + 1, claimed | cells):
                    yield [(left, ch)] + rest

    return list(walk(0, set()))


# ---------------------------------------------------------------------------
# 2 + 3. Resolve top segments by count, then by dictionary.
# ---------------------------------------------------------------------------
def load_words():
    for path in ("/usr/share/dict/words", "/usr/dict/words"):
        p = Path(path)
        if p.exists():
            words = {w.strip().lower() for w in p.read_text(errors="ignore").split()}
            if len(words) > 1000:
                return words
    # Keeps the solver self-contained where no system wordlist is installed.
    return {"farewell", "classic", "hello", "uncertain", "era"}


def decode(block, words):
    """Return [(leet_reading, english_word, tiling)] consistent with the art."""
    # Blank the "[n]" label; glyphs never start before column 4.
    top, mid, bot = ("    " + row[4:] for row in block)
    want_tops = top.count("_")

    found = []
    for parse in tile(mid, bot):
        options = [TWINS[(GLYPHS[ch][1], GLYPHS[ch][2])] for _, ch in parse]
        for combo in product(*options):
            if sum(GLYPHS[c][0] for c in combo) != want_tops:
                continue
            leet = "".join(combo)
            word = deleet(leet).strip("!.,?")
            if word in words:
                found.append((leet, word, [(l, c) for (l, _), c in zip(parse, combo)]))
    return found


def main():
    argv = [a for a in sys.argv[1:] if a != "-v"]
    verbose = "-v" in sys.argv[1:]
    src = Path(argv[0]) if argv else Path(__file__).with_name("challenge.txt")

    blocks = [b.split("\n")[:3] for b in src.read_text().split("\n\n") if b.strip()]
    words = load_words()

    parts = []
    for i, block in enumerate(blocks, 1):
        found = decode(block, words)
        readings = {(leet, word) for leet, word, _ in found}
        if len(readings) != 1:
            raise SystemExit(f"block {i}: expected one reading, got {sorted(readings)}")
        leet, word, parse = found[0]
        parts.append(leet)
        print(f"  [{i}]  {leet:<10}  {word}")
        if verbose:
            width = max(len(r) for r in block)
            for left, ch in parse:
                cell = [r.ljust(width)[left:left + 3] for r in block]
                print(f"        col {left:>2}  {cell[0]!r} {cell[1]!r} {cell[2]!r}  -> {ch}")

    print("\n  ASIS{" + "_".join(parts) + "}")


if __name__ == "__main__":
    main()
