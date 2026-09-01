// ESLint config for the blamepost mail server.
//
// Posture: catch bug-class problems (undefined references, unused
// variables, redeclarations, equality slips, control-flow issues).
// Don't enforce style ("var" vs "const", arrow-vs-function, and so on).
// The codebase has settled conventions documented in CONTRIBUTING.md
// that ESLint shouldn't second-guess.
//
// Target: Node 24 LTS, CommonJS modules, ES2024 syntax. Vendored
// dependencies under lib/vendor/ and any node_modules are excluded.
//
// The browser-facing half, the opt-in JS islands under lib/web/public/,
// gets its own block with browser globals and no Node globals, so a
// `require` or `process` reference that slipped into client code fails
// the lint instead of shipping a ReferenceError to the operator's browser.
//
// Standalone (no @eslint/js / globals npm dependency) so this lints
// cleanly via `npx eslint@latest` without resolving extra peer deps.

const NODE_GLOBALS = {
  // CommonJS module system
  module:           "readonly",
  require:          "readonly",
  exports:          "writable",
  __dirname:        "readonly",
  __filename:       "readonly",
  // Node runtime
  process:          "readonly",
  Buffer:           "readonly",
  global:           "readonly",
  globalThis:       "readonly",
  console:          "readonly",
  setTimeout:       "readonly",
  setInterval:      "readonly",
  setImmediate:     "readonly",
  clearTimeout:     "readonly",
  clearInterval:    "readonly",
  clearImmediate:   "readonly",
  queueMicrotask:   "readonly",
  performance:      "readonly",
  structuredClone:  "readonly",
  // Web-platform APIs that Node 24 ships
  fetch:            "readonly",
  crypto:           "readonly",
  URL:              "readonly",
  URLSearchParams:  "readonly",
  TextEncoder:      "readonly",
  TextDecoder:      "readonly",
  AbortController:  "readonly",
  AbortSignal:      "readonly",
  Event:            "readonly",
  EventTarget:      "readonly",
  Blob:             "readonly",
  // Modern intrinsics
  BigInt:           "readonly",
  Atomics:          "readonly",
  SharedArrayBuffer:"readonly",
  WeakRef:          "readonly",
  FinalizationRegistry: "readonly",
};

// Browser surface for the opt-in islands. Deliberately excludes every
// Node global, so client code that reaches for `require` or `process`
// fails `no-undef` here rather than at runtime in the operator's browser.
const BROWSER_GLOBALS = {
  window:           "readonly",
  document:         "readonly",
  navigator:        "readonly",
  location:         "readonly",
  history:          "readonly",
  localStorage:     "readonly",
  sessionStorage:   "readonly",
  console:          "readonly",
  fetch:            "readonly",
  crypto:           "readonly",
  URL:              "readonly",
  URLSearchParams:  "readonly",
  FormData:         "readonly",
  Headers:          "readonly",
  Request:          "readonly",
  Response:         "readonly",
  TextEncoder:      "readonly",
  TextDecoder:      "readonly",
  AbortController:  "readonly",
  AbortSignal:      "readonly",
  Event:            "readonly",
  EventTarget:      "readonly",
  CustomEvent:      "readonly",
  Blob:             "readonly",
  File:             "readonly",
  FileReader:       "readonly",
  WebSocket:        "readonly",
  EventSource:      "readonly",
  MutationObserver: "readonly",
  IntersectionObserver: "readonly",
  requestAnimationFrame: "readonly",
  cancelAnimationFrame:  "readonly",
  setTimeout:       "readonly",
  setInterval:      "readonly",
  clearTimeout:     "readonly",
  clearInterval:    "readonly",
  queueMicrotask:   "readonly",
  structuredClone:  "readonly",
  HTMLElement:      "readonly",
  customElements:   "readonly",
};

const COMMON_RULES = {
  // Bug-class rules
  "no-undef":                  "error",
  "no-redeclare":              "error",
  "no-const-assign":           "error",
  "no-delete-var":             "error",
  "no-shadow-restricted-names":"error",
  "no-global-assign":          "error",
  "no-import-assign":          "error",
  "no-func-assign":            "error",
  "no-class-assign":           "error",
  "no-this-before-super":      "error",
  "no-ex-assign":              "error",
  "no-cond-assign":            ["error", "except-parens"],
  "no-self-assign":            "error",
  "no-self-compare":           "error",
  "no-unreachable":            "error",
  "no-unsafe-finally":         "error",
  "no-unsafe-negation":        "error",
  "no-unsafe-optional-chaining": "error",
  "no-fallthrough":            "error",
  "no-async-promise-executor": "error",
  "use-isnan":                 "error",
  "valid-typeof":              "error",
  "getter-return":             "error",
  "no-compare-neg-zero":       "error",
  "no-constant-condition":     ["error", { checkLoops: false }],
  "no-constant-binary-expression": "error",
  "no-dupe-keys":              "error",
  "no-dupe-args":              "error",
  "no-dupe-else-if":           "error",
  "no-duplicate-case":         "error",
  "no-sparse-arrays":          "error",
  "no-invalid-regexp":         "error",
  "no-misleading-character-class": "error",
  "no-regex-spaces":           "error",
  "no-useless-backreference":  "error",
  // Wire-protocol parsers match bare CR, LF and NUL by escape inside
  // character classes; those are legitimate control characters in an
  // SMTP/IMAP grammar, so this rule is off for the codebase rather than
  // silenced line-by-line in every parser.
  "no-control-regex":          "off",
  "no-irregular-whitespace":   "error",
  "no-octal":                  "error",
  "no-debugger":               "error",
  "no-prototype-builtins":     "error",
  // Strict equality. `null` is allowed for the `== null` / `!= null`
  // null-or-undefined idiom; everything else must use `===` / `!==`.
  "eqeqeq":                    ["error", "always", { null: "ignore" }],
  "no-throw-literal":          "error",
  "no-promise-executor-return":"error",
  "default-case":              "error",
  "no-loss-of-precision":      "error",

  // Hygiene rules for code clarity and dead-code removal.
  // A value assigned and then overwritten before any read is dead code
  // that usually marks a refactor leftover or a wrong-variable slip.
  "no-useless-assignment":     "error",
  "no-unused-vars":            ["error", {
    args:                      "none",
    varsIgnorePattern:         "^_",
    caughtErrors:              "all",
    caughtErrorsIgnorePattern: "^_",
    destructuredArrayIgnorePattern: "^_",
  }],
  "no-useless-escape":         "error",
  "no-empty":                  ["error", { allowEmptyCatch: true }],
  "no-extra-boolean-cast":     "error",
  "no-unused-expressions":     ["error", { allowShortCircuit: true, allowTernary: true }],
  "no-unused-private-class-members": "error",
};

export default [
  {
    ignores: [
      "**/node_modules/**",
      "lib/vendor/**",
      "lib/web/public/vendor/**",
      "**/data/**",
      "**/.git/**",
      ".test-output/**",
      ".scratch/**",
      // Untracked working directories. They never exist in CI, so linting
      // them locally makes a full-tree run disagree with the gate it is
      // meant to reproduce, which invites scoping the local run to a
      // subset and missing what CI will catch.
      ".references/**",
      ".claude/**",
    ],
  },
  {
    files: ["**/*.js"],
    ignores: ["lib/web/public/**"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "commonjs",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "module",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  {
    files: ["lib/web/public/**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "script",
      globals:     BROWSER_GLOBALS,
    },
    rules: COMMON_RULES,
  },
];
