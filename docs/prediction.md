# Predictive local echo (design)

Status: **design** for Phase 4. Implemented in `src/term/predict.zig`, driven from the `msh`
client loop, using the cursor/mode tracker in `src/term/vt_track.zig`.

## The problem

Moonshine passes the remote PTY's **raw byte-stream straight through** to the local terminal
(that's what preserves native scrollback). We also want mosh-style **instant local echo**: when
you type `a`, you see `a` immediately instead of after a round-trip.

These two goals are in tension. Naively echoing `a` locally *and* blitting the server's echoed
`a` byte when it arrives yields `aa` — because after we locally wrote `a` the cursor advanced,
so the server's `a` lands one cell further right.

mosh avoids this by **owning the screen** (it renders predicted cells, and the authoritative
frame overwrites the same cells — idempotent). We deliberately don't own the screen. So we need a
different reconciliation that works on a byte-stream.

## The key trick: predict-and-suppress

A local prediction and the server's confirming echo are two representations of the *same* cell
change. So: **when we predict a character, we draw it locally; when the server's stream later
delivers that same character as an echo, we suppress it** (drop it from the passthrough). The
prediction and the suppression cancel exactly — the glyph is on screen once, and the cursor is
correct.

Concretely the client runs the authoritative bytes through a filter before writing them to the
local terminal:

```
predicted keystroke  → write locally now + push onto prediction queue + advance predicted cursor
authoritative byte b → if b confirms the head of the prediction queue (same printable char at the
                         expected position): DROP b (already on screen), pop the queue
                       else: this is real server output → REPAIR (below), then pass bytes through
```

## Two cursor models

`predict.zig` keeps two `VtTrack` instances:
- **auth** — fed only the authoritative server stream. Ground truth for where the server thinks
  the cursor is.
- **pred** — fed the authoritative stream **plus** our outstanding predictions. Where the screen
  *actually* is right now, including speculative glyphs.

`vt_track.predictionSafe()` (on the auth tracker) gates prediction: never predict in alt-screen /
tmux / bracketed-paste / mouse modes. That alone fixes mosh's worst over-prediction cases.

## Prediction queue

Each entry records: the byte(s) we optimistically rendered, and the `pred` cursor position at
which we rendered them. The queue is strictly ordered (typing order). We only ever confirm/repair
from the **head**.

Supported predictions (v1):
- **Printable char** (0x20–0x7E, and UTF-8 leads): echo the char, advance column.
- **Backspace** (0x7f / 0x08) when there is a pending predicted char on the current line: erase
  it locally (`\b \b`) and pop that prediction.
- Everything else is **not** predicted.

## Epochs

Like mosh, prediction runs in epochs. When the user presses a key that makes echo behavior
unpredictable — **Enter (CR/LF), ESC, Tab, any C0 control other than BS, or an arrow/nav key** —
we **close the epoch**: stop predicting and let the authoritative stream drive until the queue
drains and the cursor settles. Then a new epoch may begin. This prevents predicting through
command execution, completion, history navigation, etc.

## Repair (misprediction)

If an authoritative byte arrives that does **not** confirm the head prediction (e.g. the remote is
a no-echo password prompt, or an app switched to raw mode, or the server emitted a newline/prompt
first), we must undo the speculative glyphs before rendering truth:

1. Move the local cursor to the position of the **first** unconfirmed prediction (we recorded it).
2. Emit `CSI K` (erase to end of line) to wipe the speculative tail. (Predictions are always
   within the current input line, so single-line erase suffices in v1. If a prediction ever
   spanned a wrap, fall back to a full resync: erase from the first-prediction row down with
   `CSI J`.)
3. Clear the prediction queue and reset `pred` to `auth`.
4. Pass the authoritative bytes through normally.

Because a misprediction is visually a brief flicker at worst (speculative text replaced by truth),
and we only predict when `predictionSafe()` and in cooked line-editing, repairs are rare.

## Confidence / safety valve

- If repairs exceed a threshold within a window (e.g. the remote clearly isn't echoing), enter a
  **cooldown**: disable prediction for N ms. Re-enable when the stream looks echo-like again.
- A hard cap on outstanding predictions (e.g. 64) prevents unbounded speculation if the network
  stalls.
- Optional (polish, not v1): render predictions dim/underlined until confirmed, then the
  suppression-on-confirm leaves the already-correct glyph — restyle-on-confirm can be added later.

## Integration points

- Client loop (`main_msh.zig` / `session.zig`): today it does `stdin → conn.write(data)` and
  `data recv → stdout`. Insert `predict.zig` on both edges:
  - keystrokes: `predict.onInput(bytes)` returns what to render locally now (predictions) and
    still forwards the raw bytes to `conn.write` unchanged.
  - server data: `predict.onAuthoritative(bytes)` returns the filtered byte-stream to write to
    stdout (confirmations suppressed, repairs injected).
- `predict.zig` must be allocation-light and fed arbitrary chunk boundaries (same discipline as
  `vt_track`).

## Testing

Unit-test `predict.zig` deterministically without a network by driving it with scripted
(input, authoritative) sequences and asserting the emitted local byte-stream:
- Type `abc`, then feed authoritative echo `abc` → local output shows `abc` once (predictions),
  and the confirming echo is suppressed (no duplication).
- Type `a`, then authoritative sends `X` (misprediction) → a repair (`\b`/`CSI K`) then `X`.
- Backspace prediction erases a pending char.
- Enter closes the epoch: characters typed after Enter aren't predicted until the queue drains.
- In alt-screen (`predictionSafe()` false), nothing is predicted; authoritative passes through
  verbatim.
- A confirming echo split across two `onAuthoritative` chunks still reconciles.
