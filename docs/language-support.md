# Polyglot Language Support & Capability Matrix

CodeSpider uses a versioned analyzer interface (`internal/lang`, `InterfaceVersion = "v1"`) with explicit capability negotiation. Analyzers never claim full type-checker support when only syntactic or structural analysis is available.

| Language | Adapter | Active Capabilities | Known Limitations |
| --- | --- | --- | --- |
| **Go** (`.go`) | `stdlib go/ast + go/types + CFG` (`internal/codeintel`, `internal/analysis`) | `syntax`, `symbols`, `imports`, `types`, `calls`, `cfg`, `data_flow`, `semantic_diff`, `contracts`, `tests` | External third-party modules without compiled `.a` archives are recorded in `UnresolvedImports` rather than silently assumed type-safe. |
| **Python** (`.py`) | Isolated `python3 -I -S ast.parse` subprocess (fallback: structural scanner) | `syntax`, `symbols`, `imports`, `calls`, `semantic_diff`, `contracts`, `tests` (no `types` or `cfg`) | Syntactic AST + type annotations only; dynamic runtime attributes and cross-module inference are not modeled. Never executes target code. |
| **TypeScript / JavaScript** (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`) | `node` + `typescript.createSourceFile` when `typescript` module is resolvable; otherwise structural declaration scanner | `symbols`, `imports`, `contracts`, `tests` (+ `syntax`, `calls`, `semantic_diff` when `typescript` AST active) | Single-file AST extraction; full cross-file `tsc` type-checking requires project `node_modules`. |
| **Rust** (`.rs`) | Structural Rust item & contract extractor | `symbols`, `imports`, `contracts`, `tests`, `semantic_diff` | Does not expand procedural/declarative macros or run `rust-analyzer` trait/borrow-checker inference. |

Inspect live runtime capabilities at `GET /api/languages` or via the `inspect_symbols` agent tool.
