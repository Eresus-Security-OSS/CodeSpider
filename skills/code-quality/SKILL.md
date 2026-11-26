---
name: code-quality
description: Code quality, correctness, concurrency, resource lifecycle, and maintainability review guidelines.
---

Evaluate changed code for correctness, reliability, and long-term maintainability:

1. **Correctness & Edge Cases**
   - Nil/null dereferences, off-by-one errors, unchecked errors, or swallowed error returns.
   - Boundary conditions (empty slices/maps, zero values, negative inputs, integer overflow).

2. **Concurrency & Resource Management**
   - Data races, missing mutexes, lock ordering issues, or goroutine/thread leaks.
   - Unclosed files, HTTP response bodies, DB rows, or missing `context.Context` propagation/cancellation.

3. **Design & Maintainability**
   - Duplicated non-trivial logic that should share a helper.
   - Deeply nested control flow that can use early returns.
   - Breaking API/schema changes without backward compatibility or migration notes.

4. **Testing**
   - Missing unit tests for new behavior or bug fixes, especially error paths.

Keep comments concise, constructive, and focused on high-signal issues—skip pure style nitpicks.
