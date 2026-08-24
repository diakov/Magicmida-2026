# Magicmida 2026 Edition changelog

## 0.1-modern

- Detect PE32/PE32+ ordinal-encoded IAT slots (`IMAGE_ORDINAL_FLAG | ordinal`).
- Resolve ordinal slots against the winning module of the surrounding IAT group when the export exists.
- Preserve unresolved ordinal entries rather than fabricating an API mapping.
- Prevent a nil-thunk dereference in the OneCoreUAP post-processing path.
- Log x64-critical PE directories before writing the dump: Exception (`.pdata`), TLS, Load Config/CFG, and Delay Import.
- Brand GUI as **Magicmida 2026 Edition**.

### Why this matters for the supplied log

The values `8000000000000011`, `8000000000000002`, and `8000000000000001` match the PE32+ ordinal thunk representation. Older code reports them as unresolvable because they are not runtime API addresses. The 2026 path tries to bind them to the module selected from neighbouring IAT entries.

### Next diagnostic step

Run the same target and keep the new `[PE2026]` lines plus any `resolved ordinal` lines. Those show whether the remaining failure is imports, TLS, x64 unwind metadata, Load Config/CFG, or Delay Import.
