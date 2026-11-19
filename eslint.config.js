// SPDX-License-Identifier: Apache-2.0
/**
 * ESLint: correctness rules only. No formatting or style rules: a finding here is a likely bug
 * (a lost promise rejection, `==` coercion, an unreachable branch, dead code), never taste.
 *
 * Scope: src/**\/*.ts (type-aware, through tsconfig.test.json so the tests are read with their
 * types), hooks/*.mjs and scripts/*.mjs. Everything else is ignored.
 *
 * TypeScript 7 has no compiler API yet, so typescript-eslint reads TypeScript 6's: package.json
 * aliases `typescript` to @typescript/typescript6 (what typescript-eslint imports) and
 * `@typescript/native` to TypeScript 7 (what `tsc` runs), as the TypeScript 7.0 release notes
 * recommend. Drop the aliases once typescript-eslint supports the TypeScript 7 API.
 *
 * Considered and left out (counts on this tree when they were measured):
 * - @typescript-eslint/no-unnecessary-condition: 413 findings (303 outside tests), most of them
 *   deliberate checks on values typed more narrowly than the untrusted input they hold.
 * - @typescript-eslint/no-base-to-string: 89 (4 outside tests), each a deliberate String(unknown)
 *   of untrusted input in an error message.
 */
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

const unusedVars = {
  args: "after-used",
  argsIgnorePattern: "^_",
  // `const { omitted: _x, ...rest } = obj` is how this code drops a field.
  varsIgnorePattern: "^_",
  caughtErrorsIgnorePattern: "^_",
  destructuredArrayIgnorePattern: "^_",
};

export default defineConfig(
  {
    ignores: ["**/*", "!src/", "!src/**/", "!src/**/*.ts", "!hooks/", "!hooks/*.mjs", "!scripts/", "!scripts/*.mjs"],
  },
  {
    // A disable comment must suppress a real finding of an enabled rule.
    linterOptions: { reportUnusedDisableDirectives: "error" },
  },
  {
    files: ["src/**/*.ts", "hooks/*.mjs", "scripts/*.mjs"],
    rules: {
      // `x == null` (null or undefined) is the one deliberate loose comparison.
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-async-promise-executor": "error",
      "no-compare-neg-zero": "error",
      "no-cond-assign": "error",
      "no-constant-condition": "error",
      "no-control-regex": "error",
      "no-dupe-else-if": "error",
      "no-dupe-keys": "error",
      "no-duplicate-case": "error",
      "no-empty-character-class": "error",
      "no-fallthrough": "error",
      "no-invalid-regexp": "error",
      "no-self-assign": "error",
      "no-self-compare": "error",
      "no-sparse-arrays": "error",
      "no-unreachable": "error",
      "no-unsafe-finally": "error",
      "no-unsafe-negation": "error",
      "no-unsafe-optional-chaining": "error",
      "no-unused-private-class-members": "error",
      "no-unused-vars": ["error", unusedVars],
      "use-isnan": "error",
      "valid-typeof": "error",
    },
  },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { project: "./tsconfig.test.json", tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": ["error", unusedVars],
      // Promise.all over [promise, null, ...] is deliberate where an item needs no lookup.
      "@typescript-eslint/await-thenable": ["error", { allowMixedPromiseArrays: true }],
      "@typescript-eslint/no-array-delete": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-for-in-array": "error",
      "@typescript-eslint/no-implied-eval": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unsafe-unary-minus": "error",
      "@typescript-eslint/prefer-promise-reject-errors": "error",
    },
  },
);
