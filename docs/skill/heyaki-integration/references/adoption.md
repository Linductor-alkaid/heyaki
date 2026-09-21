# Make This Skill Available To A Downstream AI

An AI started in an application repository cannot automatically discover a
skill kept in Heyaki's source tree. Use one of these explicit paths.

## Read It In Place

When Heyaki is cloned, vendored, or checked out beside the application,
give the agent this instruction:

```text
Read /path/to/heyaki/docs/skill/heyaki-integration/SKILL.md before integrating Heyaki.
```

Use the actual checked-out path. This is the lowest-cost option and keeps
the agent on the exact library revision in use.

## Copy It With The Application

Copy the complete `docs/skill/heyaki-integration/` directory into a
documented location in the application repository, then put its exact
`SKILL.md` path in that project's agent instruction or task prompt. Keep
the `references/` directory beside it; the entry file links to it.

Refresh the copy whenever Heyaki is upgraded. Do not copy only `SKILL.md`,
because the capability cards are loaded on demand.

## Select The Right Audience

`heyaki-integration` is for using the library in an application. Heyaki's
own repository instructions (`AGENTS.md`) and `docs/todolists/` are for
changing Heyaki itself — do not load them for integration work. Questions
about the pinned `executor` concurrency layer (threads, channels,
scheduling APIs) belong to executor's `executor-integration` skill
(`third_party/executor/docs/skill/` when working inside this repository).
