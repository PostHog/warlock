# @posthog/warlock

Security scanner for PostHog's agentic flows. Detects poisoned context, prompt injection, secret exfiltration, and other threats using [YARA-X](https://virustotal.github.io/yara-x/) rules.

Engine-only by design — consumers decide when and what to scan.

## Installation

```bash
pnpm install @posthog/warlock
```

## Usage

```typescript
import { scan } from '@posthog/warlock';

const result = await scan(someContent);
if (result.matched) {
  for (const match of result.matches) {
    console.log(`Rule matched: ${match.rule}`);
    console.log(`Severity: ${match.metadata.severity}`);
  }
}
```

## Development

```bash
pnpm install      # install dependencies
pnpm test         # run tests
pnpm test:watch   # run tests in watch mode
pnpm build        # compile TypeScript and copy rule files to dist/
```
