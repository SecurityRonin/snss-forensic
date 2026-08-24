# snss-forensic

Forensic analyzer over the Chromium/Brave SNSS session-restore reader. Emits graded `forensicnomicon::report` observations — navigation records the reader could not decode, and window last-active timestamps outside the range the format could have written — each an observation (“consistent with”), never a conclusion. Re-exports the reader surface.

It deliberately does **not** flag a truncated tail (Brave appends to live session files, so the final record is normally half-written) — grading that would fire on every live profile.

Part of the [`snss-forensic`](https://github.com/SecurityRonin/snss-forensic) workspace: the parser is a reader (`snss-core`) plus this analyzer (`snss-forensic`), per fleet ADR-0008 / ADR-0009 (every parser is a reader **and** an analyzer).
