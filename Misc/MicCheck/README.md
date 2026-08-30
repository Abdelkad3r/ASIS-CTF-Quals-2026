# Mic Check

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Misc |
| **Difficulty** | Baby |
| **Files** | [`challenge/readouts.txt`](challenge/readouts.txt) |
| **Solver** | [`solution/solve.py`](solution/solve.py) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/96cdf208-78ac-4b31-a496-d065ccd7ea93) |
| **Flag** | `ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}` |

> The analog signals have died out. Only kind human eyes can still decode the vintage
> LED displays before the machines take over.
>
> Read the following digital readouts below. Join the blocks with `_` inside `ASIS{...}`
> (all lowercase):

```
[1]  _       _   _       _
    |_  |_| |_|  _| | |  _| |  |
    |     | |\   _| |/|  _| |_ |_

[2]  _       _   _   _
    |   |   |_| |_  |_   | |
    |_  |_    |  _|  _|  | |_

[3]      _            _
    |_|  _| |   |   | |
    | |  _| |_  |_  |_|

[4]      _   _   _   _  _|_      _
    | | | | |    _| |_|  |  |_| | | |
    |_| | | |_   _| |\   |    | | | |

[5]  _   _
     _| |_| |_| |
     _| |\    | .
```

---

## TL;DR

Each block is a row of **seven-segment (LED) glyphs** drawn in ASCII, spelling one
leetspeak word. Decode the five words and join them with `_`:

```
ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
        │        │       │       │      │
     farewell  classic  hello  uncertain  era!
```

The only real difficulty is that the art is **proportionally spaced** and its
**top-segment row is misaligned by one to two columns** in three of the five blocks —
enough to make a naive column-slicing decoder produce `cl9ss1l` and `unc3rt4n1`.
Section 6 shows how to resolve that without guessing.

---

## 1. Reading the prompt

The flavour text is the hint:

* *"vintage LED displays"* — seven-segment displays, the kind found on a bench
  multimeter or a clock radio.
* *"Only kind human eyes can still decode"* — the art is deliberately hostile to OCR
  but trivial for a human. There is no file, no cipher, no stego. What you see is
  what you decode.

Three rows per block is the giveaway. A seven-segment digit needs exactly three text
rows to draw:

```
 _     <- a          top
|_|    <- f g b      upper verticals + middle bar
|_|    <- e d c      lower verticals + bottom bar
```

Seven segments, conventionally named `a`–`g`:

| Segment | Position | Drawn as |
|---|---|---|
| `a` | top | `_` in row 0, centre column |
| `b` | upper right | `\|` in row 1, right column |
| `c` | lower right | `\|` in row 2, right column |
| `d` | bottom | `_` in row 2, centre column |
| `e` | lower left | `\|` in row 2, left column |
| `f` | upper left | `\|` in row 1, left column |
| `g` | middle | `_` in row 1, centre column |

The art adds three non-standard glyphs that a pure seven-segment display cannot
produce — a diagonal `\` for `r`, a diagonal `/` for `w`, and a `_|_` crossbar for `t`.
Those are the "kind human eyes" concession.

## 2. Building the font

Working out the alphabet from the blocks themselves gives sixteen glyphs. `4/a`,
`3/e`, `1/i`, `0/o` are the leetspeak substitutions; every other character is a
literal letter:

```
 _           _     _                 _     _
|_    |_|   |_|    _|   | |   |     |     |_
|       |   |\     _|   |/|   |_    |_     _|
 f    4=a    r    3=e    w     l     c     s

             _           _    _|_    _
|     |_|   | |   | |   | |    |    |_|   |
|     | |   |_|   |_|   | |    |      |   .
1=i    h    0=o    u     n     t    9=g    !
```

Two observations that matter later:

1. **`4` and `9` differ only in the top segment.** So do `l` and `c`, and `u` and `0`.
   These three pairs are the *only* ambiguity in the font — every other glyph is fully
   determined by its two lower rows.
2. **Glyph widths vary.** `1` is a single column, `t` occupies all three columns of the
   top row, the rest are the usual 3×3 cell. There is no fixed pitch to slice on.

## 3. Establishing the column grid

The safe way to read the art is to index it by column rather than eyeball it. For
block 1:

```
top row  '_' at columns : [5, 13, 17, 25]
row 1 ink at columns   : 4| 5_ 8| 9_ 10| 12| 13_ 14| 17_ 18| 20| 22| 25_ 26| 28| 31|
row 2 ink at columns   : 4| 10| 12| 13\ 17_ 18| 20| 21/ 22| 25_ 26| 28| 29_ 31| 32_
```

Cells begin at columns 4, 8, 12, 16, 20, 24, 28, 31 — a pitch of four that breaks at
the end, because the two trailing `l` glyphs are packed tighter. Decoding cell by cell:

```
[1]  f4r3w3ll    farewell
      col  4  ' _ ' '|_ ' '|  '  -> f
      col  8  '   ' '|_|' '  |'  -> 4
      col 12  ' _ ' '|_|' '|\ '  -> r
      col 16  ' _ ' ' _|' ' _|'  -> 3
      col 20  '   ' '| |' '|/|'  -> w
      col 24  ' _ ' ' _|' ' _|'  -> 3
      col 28  '   ' '|  ' '|_ '  -> l
      col 31  '   ' '|  ' '|_ '  -> l
```

`f4r3w3ll` → **farewell**. The theme of the challenge is now confirmed, and blocks 3
and 5 fall out the same way:

```
[3]  h3ll0       hello
[5]  3r4!        era!      (the last glyph is a stroke over a dot: '!')
```

## 4. The leetspeak mapping

| Glyph | `4` | `3` | `1` | `0` | `9` |
|---|---|---|---|---|---|
| Letter | `a` | `e` | `i` | `o` | `g` |

Note that `s` is written as the letter `s`, not as `5` — the two are drawn identically,
and the surrounding words (`classic`, `farewell`) settle it.

## 5. Where a naive decoder breaks

Blocks 2 and 4 do not decode cleanly, and both failures come from the same source: the
**top-segment row of the published art is not aligned with the glyphs beneath it.**

**Block 2** — the underscores sit at columns 5, 13, 17, 21, while the glyph cells start
at 4, 8, 12, 16, 20, 25, 27. Read literally, the third glyph gains a top bar it should
not have (`4` → `9`) and the last glyph loses the one it should have (`c` → `l`):

```
naive:  c l 9 s s 1 l     ->  "clgssil"   not a word
```

**Block 4** — worse. The final underscore sits at column 33, two columns left of where
it belongs. That single stray `_` bridges the gap between the `1` at column 32 and the
`n` at column 34, welding two glyphs into one run of ink. A decoder that segments on
"runs of inked columns" reads them in the wrong order:

```
naive:  u n c 3 r t 4 n 1  ->  "uncertani"  not a word
```

Both are recoverable, but not by trusting pixel positions.

## 6. Two constraints that resolve it

The fix is to stop treating the top row as positional evidence and start treating it as
a **count**.

**Constraint A — the underscore count is drift-independent.** However far an underscore
has slid sideways, it is still there. Block 2's top row holds exactly four underscores,
so exactly four of its seven glyphs carry a top segment. Block 4 holds seven (note `t`
contributes two, being drawn `_|_`).

**Constraint B — only three glyph pairs are ambiguous.** From §2, the lower two rows
pin down every glyph except `4/9`, `l/c` and `u/0`. So the search space is tiny.

Applying both to block 2 — the lower rows fix glyphs 4, 5 and 6 as `s`, `s`, `1`
(contributing `1 + 1 + 0 = 2` top segments), leaving glyphs 1, 2, 3 and 7 free:

| Reading | Top segments (`g1+g2+g3` + fixed `ss1` + `g7`) | De-leeted | Word? |
|---|---|---|---|
| `cl9ss1l` | 1+0+1+2+0 = 4 ✓ | clgssil | ✗ |
| `cc4ss1l` | 1+1+0+2+0 = 4 ✓ | ccassil | ✗ |
| `ll9ss1c` | 0+0+1+2+1 = 4 ✓ | llgssic | ✗ |
| **`cl4ss1c`** | **1+0+0+2+1 = 4 ✓** | **classic** | **✓** |

And to block 4, where the ambiguity is the *tiling* rather than the glyph identity:

| Tiling | Reading | Top segments (`g1+g2+g3` + fixed `ss1` + `g7`) | De-leeted | Word? |
|---|---|---|---|---|
| `n` at col 32, `1` at col 36 | `unc3rt4n1` | 7 ✓ | uncertani | ✗ |
| **`1` at col 32, `n` at col 34** | **`unc3rt41n`** | **7 ✓** | **uncertain** | **✓** |

Exactly one reading of each block survives both constraints plus a dictionary check.
Nothing here is a guess.

## 7. Automated solve

[`solution/solve.py`](solution/solve.py) implements the above directly against the unmodified art:

1. **`tile()`** exhaustively tiles the two *reliable* rows with glyph cells, keeping
   only tilings that consume every inked column. Cells may overlap on blank columns, so
   a one-column `1` followed by a `c` is handled without a pitch assumption.
2. Each glyph is then allowed to swap with its top-segment twin (`4/9`, `l/c`, `u/0`),
   and candidates are filtered to those whose total top-segment count matches the number
   of underscores in the top row.
3. Survivors are de-leeted and checked against `/usr/share/dict/words`.

```console
$ python3 solution/solve.py
  [1]  f4r3w3ll    farewell
  [2]  cl4ss1c     classic
  [3]  h3ll0       hello
  [4]  unc3rt41n   uncertain
  [5]  3r4!        era

  ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```

Every block yields **exactly one** reading — the script aborts if any block is
ambiguous, so the output is a proof rather than a preference. Run with `-v` to dump the
per-glyph cell trace shown in §3.

## 8. Flag

```
ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```

Read as prose: *farewell classic, hello uncertain era!* — which is the challenge
description restated, and a good sanity check that the decode is right.

## 9. Takeaways

* **Three-row ASCII art is almost always a seven-segment display.** Build the font
  from the art itself rather than importing one; challenge authors add glyphs (`r`,
  `w`, `t`, `!` here) that no real seven-segment display can render.
* **Segment on the rows you trust.** The lower two rows carry the verticals and are
  self-aligning; the top row is a single sparse character per glyph and is exactly
  where whitespace damage hides — in copy-paste, in a terminal, or in the original art.
* **Turn a positional signal into a counting signal when position is unreliable.** The
  number of top segments survives any horizontal drift, and it was enough to close both
  ambiguities here.
* **Let the plaintext arbitrate.** With a leetspeak mapping and a wordlist, the search
  space of a warm-up encoding collapses to a single reading. If a decode is not a word,
  the decode is wrong — not the wordlist.
