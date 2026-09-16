# START HERE — building ScanLedger with Claude Code

Everything Claude Code needs is already in this folder. Follow these steps.

## What's in this folder

```text
ScanLedger/
  CLAUDE.md          Always-loaded guardrails (Claude Code reads this every session)
  START_HERE.md      This file
  docs/
    PRD.md           The requirements — the source of truth
    HANDOFF.md       The implementation brief (pre-answers, checkpoints, safety rules)
    ScanLedger_PRD_reading_copy.docx   The formatted Word copy, for reading only
```

Do not rename `CLAUDE.md`, `docs/PRD.md`, or `docs/HANDOFF.md` — the prompts
point at those exact paths.

## Steps (Windows)

1. Put this whole `ScanLedger` folder wherever you keep code (for example on your
   Desktop). This folder becomes the repository root.
2. Open the folder in VS Code, open the integrated terminal, and run:

   ```
   claude
   ```

   (If `claude` isn't found, install Claude Code first — it's a separate CLI tool
   from the Claude chat app.)
3. Paste the kickoff prompt below as your first message.
4. Claude Code will read the docs, summarize, and ask you up to five questions,
   then stop. Answer them. It will then propose a milestone plan and wait for your
   approval before building. Bring its summary, questions, and plan back to the
   review chat before you approve.

## Settings that matter for this project

- **Do not enable blanket auto-accept.** This is a security-boundary build; you
  want to review at each checkpoint. Let Claude Code stop and ask.
- Build **one checkpoint at a time**, ScanGuard and the governor first. Approve
  each checkpoint before the next starts.
- If it ever says a test or build passed, ask to see the actual command output.

## The kickoff prompt — paste this first

---

Read `CLAUDE.md`, `docs/PRD.md`, and `docs/HANDOFF.md` in full before doing
anything. `docs/PRD.md` is the source of truth; if the handoff and the PRD
disagree, the PRD wins.

Do NOT write any code, files, or scaffolding yet. First complete the "Before you
write any code" sequence from `docs/HANDOFF.md`:

1. Summarize the product, the scope-lock boundary, the MVP release boundary, and
   the architecture in no more than 300 words.
2. List the contradictions, hidden assumptions, provider limitations, and safety
   concerns you see. The PRD's own review already fixed a set of these; find what
   it missed rather than restating it.
3. Review the pre-answered project questions in the handoff, then ask up to five
   consequential questions that neither the PRD nor those answers resolve.
4. Give your view on the highest-risk implementation decision and how to de-risk
   it.

Then stop and wait for my answers. After I answer, propose the milestone plan
from the handoff and wait for my approval before you create anything. When we
start building, go one checkpoint at a time — ScanGuard and the governor first —
and stop at each checkpoint boundary for my review.
