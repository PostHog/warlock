# Changelog

## [0.2.4](https://github.com/PostHog/warlock/compare/v0.2.3...v0.2.4) (2026-07-24)


### Bug Fixes

* **rules:** don't flag config-doc opt-out framing in posthog_feature_attack ([#63](https://github.com/PostHog/warlock/issues/63)) ([51a5a98](https://github.com/PostHog/warlock/commit/51a5a98ad20c8ed93386f81312e513b28848388b))

## [0.2.3](https://github.com/PostHog/warlock/compare/v0.2.2...v0.2.3) (2026-07-07)


### Bug Fixes

* stop PII rule matches bleeding across call boundaries ([#59](https://github.com/PostHog/warlock/issues/59)) ([31f5834](https://github.com/PostHog/warlock/commit/31f5834b90ea707a7dc01ad978e36b0246f130f6))

## [0.2.2](https://github.com/PostHog/warlock/compare/v0.2.1...v0.2.2) (2026-06-08)


### Bug Fixes

* **ci:** use npm publish + pin npm 11.6.4 for OIDC trusted publishing ([#45](https://github.com/PostHog/warlock/issues/45)) ([7563256](https://github.com/PostHog/warlock/commit/75632562c81cf8badb54671c1c2b711f0fb505fe))

## [0.2.1](https://github.com/PostHog/warlock/compare/v0.2.0...v0.2.1) (2026-06-08)


### Bug Fixes

* **ci:** clear NODE_AUTH_TOKEN placeholder for OIDC trusted pub ([#43](https://github.com/PostHog/warlock/issues/43)) ([fcb8b6f](https://github.com/PostHog/warlock/commit/fcb8b6fdf2cede833d44d6f4833682ce8e6b29aa))

## [0.2.0](https://github.com/PostHog/warlock/compare/v0.1.0...v0.2.0) (2026-06-08)


### Features

* add LLM traige ([#27](https://github.com/PostHog/warlock/issues/27)) ([e8c0ce4](https://github.com/PostHog/warlock/commit/e8c0ce461542486f4b5e9dbb350406735f10981e))
* initial release + publishing infrastructure ([#36](https://github.com/PostHog/warlock/issues/36)) ([5cf7514](https://github.com/PostHog/warlock/commit/5cf7514d0442ed0766718fea5977a7df32cde694))


### Bug Fixes

* add pnpm-workspace.yaml with allowBuilds for esbuild ([#29](https://github.com/PostHog/warlock/issues/29)) ([243aa0f](https://github.com/PostHog/warlock/commit/243aa0f231f4ed872efacf0ec04a32d8b964d9fd))
* more resilient triage ([#32](https://github.com/PostHog/warlock/issues/32)) ([3995722](https://github.com/PostHog/warlock/commit/39957221e6225c4c8d00d26af522dab0dd3a951b))
