// SPDX-License-Identifier: Apache-2.0
/**
 * Changelog entry classification and sanitisation.
 *
 * A changelog is third-party text that ends up in an agent's context, so
 * every entry is cleaned before it leaves this module: ASCII control
 * characters and the zero-width / bidi-override code points that make text
 * render differently from how it reads (U+200B–U+200F, U+202A–U+202E,
 * U+2066–U+2069, U+FEFF) are stripped, whitespace is collapsed, and each
 * entry is capped at 400 characters so one runaway paragraph cannot crowd
 * out the rest of the report.
 *
 * Classification is keyword-based on purpose: changelogs follow no schema,
 * and a wrong guess is cheap here because every entry carries its text — the
 * kind decides ordering and what concise mode keeps, never whether an entry
 * exists. An explicit section heading ("### Breaking Changes", keep-a-
 * changelog's "### Removed" / "### Deprecated" / "### Security") outranks
 * keywords in the line itself.
 */

export type EntryKind = "breaking" | "deprecation" | "security" | "change";

export const MAX_ENTRY_CHARS = 400;

const CONTROL = /[\u0000-\u0009\u000B-\u001F\u007F]/g;
const INVISIBLE = /[​-‏‪-‮⁦-⁩﻿]/g;

/** Strip control and invisible/bidi characters, collapse whitespace, cap length. */
export function sanitizeEntry(text: string, cap: number = MAX_ENTRY_CHARS): string {
  const clean = text.replace(INVISIBLE, "").replace(CONTROL, " ").replace(/\s+/g, " ").trim();
  return clean.length > cap ? `${clean.slice(0, cap - 1)}…` : clean;
}

/**
 * Explicit markers: these win even over a security keyword in the same line.
 * Upper-case BREAKING and conventional-commit `feat!:` are case-sensitive
 * markers; the prose form must not be negated — tokio 1.44.0's entry
 * "We determined this change is not a breaking change" was counted as
 * breaking on the first live run.
 */
// `BREAKING` but not the file name `BREAKING-CHANGES.md` (ratatui links it from routine entries);
// a leading "Breaking -" / "[Breaking]" label too (webpack-merge 5, handlebars-rust).
// Case-sensitive on purpose: lowercase "breaking" is prose, handled (with negation) below.
// "*Backwards-incompatible*:" (marshmallow 4) is the same call in other words.
const EXPLICIT_BREAKING_MARKER =
  /\bBREAKING\b(?![-_.]\w)|⚠|^\s*\*{0,2}\w+(?:\([^)]*\))?!:|^\s*\*{0,2}[Bb]reaking\*{0,2}\s*(?::|[-–—]\s)|^\s*\[(?:[Bb]reaking|[Rr]emoved)\]|\b[Bb]ackwards?[- ][Ii]ncompatible\b/;
/**
 * Text ABOUT breaking changes rather than one: a pointer to the list ("⚠️ List
 * of breaking changes can be found here"), a CI label check, a docs fix
 * (ratatui 0.24-0.26: 8 of 16 marker-based flags on 2026-10-03 were these).
 */
const META_BREAKING =
  /\b(?:list|lists|see|found|documented|described|summary|guide|doc|docs|documentation|label|labels|check|technically|despite|mentioning)\b[^.]{0,40}\bbreaking[- ]changes?\b|\bbreaking[- ]changes?\b[^.]{0,30}\b(?:can be found|are (?:listed|documented|described)|described|label|labels|doc|docs|documentation)\b|BREAKING[-_]CHANGES/i;
/**
 * Intent, not a change: "We reserve the right to drop support for ...",
 * "will be removed in a future release".
 */
const FUTURE_INTENT =
  /\b(?:reserve the right|will(?: be)?|may(?: be)?|might|plan(?:s|ning)? to|intend(?:s)? to|in (?:a|the) future|eventually)\b[^.]{0,40}\b(?:drop|dropp|remov|renam|deprecat)/i;
/** A fix-led entry ("Fixed nightly build where Generator was renamed to Coroutine"): removal words in it are prose. */
const LEADING_FIX = /^\W*(?:\*\*[^*]{1,40}\*\*:?\s*)?(?:fix|fixed|fixes|fixing)\b/i;
/**
 * "breaking change" in prose, except when negated, when it is a compound
 * ("reproducibility-breaking": rand 0.9's changed outputs, not its API), and
 * when it names another crate's release (regex 1.10: "`regex-syntax` breaking
 * change release"). Measured 2026-10-02 against a 3-rater panel.
 */
const EXPLICIT_BREAKING_PROSE = /(?<!\bnot (?:a )?|\bnon[- ]|\bno |-)\bbreaking[- ]changes?\b(?! release)/i;
/** A yank notice mentions breakage without being a change to the API ("Yanked ... due to unforeseen breaking change"). */
const YANK_NOTICE = /\byanked\b/i;
/**
 * Inline labels that say an entry is NOT a breaking change (axum's
 * `**fixed:** Removed the warning about breaking changes from README`,
 * conventional `fix:` / `docs:`). Such entries keep only their security and
 * deprecation signal; removal/rename keywords inside them are prose.
 */
const NON_BREAKING_LABEL =
  /^\s*\*{0,2}(?:fixed|fix|fixes|added|add|feat|features?|docs?|perf|chore|internal|improved|tests?|ci|build|refactor|style)(?:\([^)]*\))?\*{0,2}:\*{0,2}\s/i;
const SECURITY = /\bsecurity\b|\bCVE-\d{4}-\d+|\bGHSA-[\w-]+|\bRUSTSEC-\d{4}-\d+|vulnerab/i;
/**
 * Wording that changes the API a caller compiles or runs against. Each pattern
 * is narrower than the keyword it replaced: bare "no longer" also matched
 * "No longer panics when ..." (a fix), bare "MSRV" matched "Add
 * `Cargo.lock.msrv` file", and only past-tense "removed"/"renamed" were seen,
 * so rand 0.9's "Rename fn `thread_rng()` to `rng()`" was missed.
 *
 * Removal and rename wording is breaking unless what went is internal (see
 * INTERNAL_CHANGE); the other API wording stands whatever else the line mentions
 * ("MSRV is now 1.70 because of a dependency update").
 */
const REMOVAL_HEURISTIC = new RegExp(
  [
    "\\bremoved\\b",
    "\\bremoves\\b",
    "\\b(?:has|have|was|were) been dropped\\b",
    "\\brenamed?\\b",
    // The removed thing is the object of "remove": a code name within a few words
    // ("Remove first parameter (`rng`) of ..."), not a backtick somewhere later
    // ("Remove a window when ... `cd`able", a security fix).
    "^\\W*(?:remove|delete)\\b(?:\\s+[\\w-]+){0,3}\\s*\\(?`",
    // ... or a qualified name without backticks ("remove Socket#rooms object").
    "^\\W*(?:remove|delete)\\b(?:\\s+[\\w-]+){0,2}\\s+[A-Za-z_]\\w*(?:#|::|\\.)[A-Za-z_]",
  ].join("|"),
  "i",
);
/** Wording that changes the API or its requirements, whatever else the line mentions. */
const BREAKING_HEURISTIC = new RegExp(
  [
    // Not "no longer require(s)": that is a relaxation ("`Data::get_ref()` no longer
    // requires `T: Sized`", four actix-web 4 entries the panel called non-breaking).
    "\\bno longer (?:accepts?|returns?|supports?|exports?|exported|exposed|re-?exports?|available|provides?|allow(?:s|ed)?|implements?|public|includes?|ships?|compiles?|works? with)\\b",
    "\\bcan no longer\\b",
    "\\bnow (?:also )?returns?\\b",
    // Rust: marking a public type non-exhaustive breaks exhaustive matches and struct literals.
    "\\b(?:now )?marked (?:as )?`?#\\[non_exhaustive\\]",
    "\\bdrop(?:ped|s)? (?:support|compatibility)\\b",
    "\\bdropped\\b.*\\b(?:support|compatibility)\\b",
    // A raise names a version: "Bump MSRV to 1.63"; "Update MSRV in cron job" (config 0.14, CI) does not.
    // A window of .{0,60}, not [^.]: versions carry dots ("MSRV: Rust 1.64.0 or later is now required").
    "\\b(?:bump|bumped|raise|raised|increase|increased|update|updated|require|requires|now)\\b.{0,60}\\b(?:MSRV|minimum supported rust version|rust-version)\\b.{0,30}\\d+\\.\\d+",
    // A raise names the new version ("MSRV is now 1.70", "MSRV: Rust 1.64.0 or later");
    // "Move MSRV metadata to `Cargo.toml`" names none.
    "\\b(?:MSRV|minimum supported rust version)\\b.{0,60}?\\b(?:is now|to|bumped to|raised to|increased to)\\s+(?:rust\\s+|rustc\\s+)?v?\\d",
    "\\b(?:MSRV|minimum supported rust version)\\b.{0,60}\\d+\\.\\d+.{0,20}\\bor later\\b",
    "\\bnow (?:requires?|required|returns?|takes?|accepts? only)\\b",
    "\\b(?:function|method|type|the) signatures?\\b",
    "\\bsignatures? (?:of|has|have|changed)\\b",
    "\\b(?:changed?|new|different)\\b[^.]{0,30}\\b(?:return|argument|parameter) types?\\b",
    "\\b(?:return|argument|parameter) types? (?:have |has )?(?:changed|change)\\b",
    "\\btypes have changed\\b",
    // An API that now implements/returns/takes a different type; "Use `Cell` instead
    // of `RefCell` in `Format`" is an internal choice, not an API change.
    "\\b(?:implements?|returns?|takes?|accepts?|requires?|yields?|expects?)\\b[^.]{0,40}`[^`]+`\\s+instead of\\s+`[^`]+`",
    "\\(instead of `",
    // An API that now receives/uses a different type, or moved out of the crate
    // (actix-web 4: "`guard::fn_guard` functions now receives a `&GuardContext`",
    // "`test::start`; moved to new `actix-test` crate").
    "\\bnow (?:receives?|uses?)\\b[^.]{0,30}`",
    "\\bmoved (?:in)?to (?:the |a )?(?:new |separate )?`?[\\w-]+`? (?:crate|package|module)\\b",
    "\\bto keep the (?:old|previous|former) behaviou?r\\b",
    "\\bincompatib",
  ].join("|"),
  "i",
);
/** Removals that change nothing a caller sees: "Removed unused imports", "Removed Webpack". */
const INTERNAL_CHANGE =
  /\b(?:unused|unneeded|unnecessary|internal(?:ly)?|dead code|tests?|ci|lint(?:ing)?|typos?|comments?|docs?|documentation|readme|redundant|duplicated?|webpack|dev-?dependenc(?:y|ies)|dependency|warnings?|examples?|benchmarks?|release process|build process|tooling|usage|incorrect|wrong|erroneous|stray|spurious|private|maintainers?|contributors?|invalid|broken|bogus|[\w-]+\.(?:md|json|ya?ml|toml|lock|txt|cfg)(?![\w(]))\b/i;
/**
 * The removed thing is private by its name (`_prepare_conn`, a leading
 * underscore): urllib3 2.0 lists such removals under "Removed".
 */
const PRIVATE_NAME = /^\W*(?:remove[sd]?|delete[sd]?|drop(?:s|ped)?)\b[^`]{0,40}`_[A-Za-z]/i;
const isInternal = (t: string): boolean => INTERNAL_CHANGE.test(t) || PRIVATE_NAME.test(t);
/** Public API made private ("Assorted array helper methods and types made private"): a removal, though it says "private". */
const MADE_PRIVATE = /\b(?:made|make|makes|is now|are now)\b[^.]{0,60}\bprivate\b/i;
/**
 * The entry says it changes nothing for users: "passing string or boolean still
 * works as before", "This change should have no effect on users".
 */
const STATED_COMPATIBLE =
  /\b(?:still works?|still work as before|continues? to work|(?:is|are) still supported|remains? supported|(?:should|will|has|have) (?:have )?no (?:effect|impact) on (?:users|you|most users|existing code)|no user-facing)\b|(?<!\bnot |\bnon-?)\bbackwards?[- ]compatib(?:le|ility)\b/i;
/**
 * Not an API change although worded like one: undoing a removal or deprecation
 * ("removes the deprecation notice from", "restore the `X()` function"), a
 * relaxation ("remove Send bounds for request `Body`"), a repository rename, a
 * swapped dependency ("Move from `winapi` to `windows` crate").
 */
const UNDO = /\bremov\w*\s+(?:the\s+)?(?:[\w`]+\s+)?(?:bounds?|restrictions?|limitations?|limits?|requirements?|constraints?|need for)\b|\brenam\w*\s+(?:the\s+)?(?:github\s+)?repo(?:sitory)?\b|\bmov(?:e|ed|es)\s+from\s+\x60[^\x60]+\x60\s+to\s+\x60[^\x60]+\x60\s+(?:crate|package|library)\b|\bremov\w*\s+(?:the\s+)?deprecation\s+(?:notices?|warnings?|messages?)\b|\bun-?deprecat|\b(?:restore[sd]?|restoring|re-?add(?:ed|s)?|reintroduc\w*)\b/i;
/** A change confined to examples, docs, tests or CI: "Drop support for Go 1.21 in dice example". */
const SCOPED_NON_API = /\bin (?:the )?(?:[\w-]+ )?(?:examples?|docs?|documentation|tests?|ci|workflows?|benchmarks?|readme)\b/i;
const LEAD = String.raw`^\W*(?:\*\*[^*]{1,40}\*\*:?\s*)?`;
/**
 * Runtime and language support: dropped versions and raised minimums ("drop
 * node 10.x", "Drop support for Go 1.21", "only support node 16-20", "Replace
 * go 1.21 with go 1.22 in go mod", "increase MSRV to 1.63"). Breaking whatever
 * the reason the entry gives ("drop node 10.x to upgrade dev dependencies").
 */
const RUNTIME_SUPPORT = new RegExp(
  [
    String.raw`\b(?:drop(?:s|ped|ping)?|remove[sd]?|removing|end(?:s|ed)?)\s+(?:official\s+)?(?:support\s+(?:for\s+)?)?(?:node(?:\.?js)?|python|py|go|golang|ruby|php|java|jdk|rust|rustc)\s*v?\d`,
    String.raw`\b(?:only supports?|now requires?|requires? at least|minimum (?:supported )?(?:version of )?)\s*(?:node(?:\.?js)?|python|go|golang|rust|ruby|php|java)\s*v?\d`,
    String.raw`\bonly supports? (?:node(?:\.?js)?|python|go|golang)\b`,
    String.raw`\bgo\s*1\.\d+[^.]{0,30}\bgo\.?\s?mod\b`,
    String.raw`\b(?:bump|bumped|raise|raised|increase|increased|update|updated|require|requires|now)\b.{0,60}\b(?:MSRV|minimum supported rust version|rust-version)\b.{0,30}\d+\.\d+`,
  ].join("|"),
  "i",
);
/**
 * Wording that changes the API whatever heading it sits under (rule set added
 * 2026-10-11 from the G3 panel's dev pairs): a leading removal or rename of
 * something API-shaped, a changed default, a type made private, a move, a
 * replacement, keyword-only arguments, "now ... instead of".
 */
const API_CHANGE = new RegExp(
  [
    // "remove UMD build", "remove `ReasonPhrase::from_bytes_unchecked()` method", "Remove previously deprecated code".
    // The removed thing is named within the next few words, as in REMOVAL_HEURISTIC: "Remove a window when ...
    // `cd`able by non-owners" (a security fix) has its backtick far later.
    String.raw`${LEAD}(?:remove[sd]?|delete[sd]?|drop(?:s|ped)?)\b(?=(?:\s+[\w.:/-]+){0,4}\s*\(?\x60|(?:\s+[\w.:/-]+){0,5}?\s+(?:support|builds?|param(?:eter)?s?|options?|methods?|functions?|modules?|class(?:es)?|types?|exports?|features?|flags?|apis?|prefix(?:es)?|constructors?|requires|imports|entry ?points?|fields?|propert(?:y|ies)|arguments?|attributes?|traits?|structs?|enums?|macros?|commands?|settings?|config|keys?|aliases?|fallback|deprecated|code)\b)`,
    String.raw`${LEAD}renamed?\b`,
    String.raw`\x60[^\x60]+\x60\s+(?:is |was |has been )?renamed\b|\bchanged? (?:the )?name of\b`,
    // Defaults: "Changed the default `blocksize` to 16KB", "now defaults `extended` to `false`", "default `header_read_timeout` to 30 seconds".
    String.raw`${LEAD}(?:change[sd]?|set|make|made)\b[^.]{0,60}\bdefaults?\b[^.]{0,60}\bto\b`,
    String.raw`${LEAD}default\s[^.]{0,60}\bto\b`,
    String.raw`\bnow defaults?\b[^.]{0,40}\bto\b|\bdefaults? (?:value |values )?(?:is|are) now\b`,
    String.raw`\b(?:keyword|positional)[- ]only\b`,
    String.raw`\x60[^\x60]+\x60\s+(?:has been |have been |was |were |is |are )?moved (?:to|into|out of)\b`,
    String.raw`${LEAD}moved?\b[^.]{0,80}\x60[^\x60]+\x60[^.]{0,60}\b(?:to|into|out of)\b`,
    String.raw`\b(?:are|is|was|were|been)\s+(?:both\s+)?replaced\b|\x60[^\x60]+\x60\s+replaces\s+\x60`,
    String.raw`\bnow\b[^.]{0,60}\binstead of\b`,
    String.raw`\b(?:accepts?|takes?|returns?|receives?)\s+(?:a |an )?(?:pointer|reference|value|slice|copy)\b[^.]{0,30}\binstead of\b`,
    String.raw`\bchang(?:e|ed|es)\b[^.]{0,80}\bfrom\s+\x60[^\x60]+\x60\s+to\s+\x60`,
    String.raw`\bno longer (?:subclass(?:es)?|inherits?|comparable|usable|considers?|escapes?|initiali[sz]ed|quotes?|sets?|ha(?:s|ve) a default|safe|valid|recogni[sz]ed|parsed?|emitted|exposed|called)\b|\bis not set anymore\b|\bnot set anymore\b`,
  ].join("|"),
  "i",
);

/**
 * The text classified: RST ``literals`` read as `literals`, link targets and
 * bare URLs dropped (a `go.dev/doc/go1.21` link made "Drop support for Go 1.21"
 * read as a docs change), GitHub's "by @user in <PR url>" suffix dropped.
 */
export function classificationText(text: string): string {
  return text
    .replace(/``/g, "`")
    .replace(/\]\([^)]*\)/g, "]")
    .replace(/\bby @[\w-]+(?:\[bot\])? in\s+\S+/g, " ")
    .replace(/https?:\/\/\S+/g, " ");
}
const DEPRECATION = /deprecat/i;
/**
 * An entry whose main verb is "deprecate" is a deprecation even when it names
 * the replacement ("Deprecated `Itertools::group_by` (renamed `chunk_by`)"):
 * the old name still works.
 */
const LEADING_DEPRECATION = /^\W*(?:\*\*[^*]{1,40}\*\*:?\s*)?(?:deprecated?|deprecates|deprecating)\b/i;

/** Kind of a single changelog line by its own wording. */
export function classifyText(raw: string): EntryKind {
  const text = classificationText(raw);
  if (META_BREAKING.test(text)) return SECURITY.test(text) ? "security" : "change";
  if (EXPLICIT_BREAKING_MARKER.test(text)) return "breaking";
  if (STATED_COMPATIBLE.test(text)) return DEPRECATION.test(text) ? "deprecation" : "change";
  if (NON_BREAKING_LABEL.test(text)) {
    if (SECURITY.test(text)) return "security";
    return DEPRECATION.test(text) ? "deprecation" : "change";
  }
  if (YANK_NOTICE.test(text)) return "change";
  if (LEADING_DEPRECATION.test(text)) return "deprecation";
  // A rename that keeps the old name working ("Rename `x => y`, deprecating the old name").
  if (/\brenam/i.test(text) && DEPRECATION.test(text) && !/\bremov/i.test(text)) return "deprecation";
  if (EXPLICIT_BREAKING_PROSE.test(text)) return "breaking";
  if (SECURITY.test(text)) return "security";
  if (FUTURE_INTENT.test(text)) return DEPRECATION.test(text) ? "deprecation" : "change";
  if (UNDO.test(text)) return DEPRECATION.test(text) ? "deprecation" : "change";
  if (!SCOPED_NON_API.test(text)) {
    if (RUNTIME_SUPPORT.test(text) || BREAKING_HEURISTIC.test(text)) return "breaking";
    if (MADE_PRIVATE.test(text) && !LEADING_FIX.test(text)) return "breaking";
    if (API_CHANGE.test(text) && !isInternal(text) && !LEADING_FIX.test(text)) return "breaking";
  }
  if (REMOVAL_HEURISTIC.test(text) && !isInternal(text) && !LEADING_FIX.test(text)) return "breaking";
  if (DEPRECATION.test(text)) return "deprecation";
  return "change";
}

/**
 * What a sub-heading (or a label-only bullet such as express's "* remove:")
 * says about the entries under it:
 * - an EntryKind: the author's explicit call ("BREAKING CHANGES", "⚠",
 *   changesets' "Major Changes", "Security", "Deprecated");
 * - "removal": a removal list ("Removed", "remove:", "API changes"), breaking
 *   except for internal clean-up and deprecation notices filed under it (axios
 *   1.0 removed "unused imports" there; nix files deprecations under Removed);
 * - "additive": additions and fixes ("Added", "Fixed", "Features", "Other"),
 *   where only an explicit marker makes an entry breaking ("Added a clear()
 *   function ... removed from an axios instance" is not a removal).
 */
export type EntryContext = EntryKind | "removal" | "additive" | "fixes";

const FIX_HEADING = /^\W*(?:fixed|fixes|bug ?fixes|bugfixes|fix)\W*$/i;

// "Other changes" / "Misc" are not additive: pgx 5 files its type removals and renames
// under "Other Changes", and marshmallow 4 a changed base class.
const ADDITIVE_HEADING =
  /^\W*(?:added|adds|new|new features?|features?|enhancements?|improvements?|fixed|fixes|bug ?fixes|performance(?: improvements)?|perf|optimi[sz]ations?|docs?|documentation|tests?|testing|internal|chores?|ci|build|refactor(?:ing)?)\W*$/i;

/** Context implied by a heading or label, or null when it carries no signal ("### Changed"). */
export function classifyHeading(heading: string): EntryContext | null {
  if (/(?<!-)\bbreaking\b|⚠|incompatib|migration|\bmajor changes?\b/i.test(heading)) return "breaking";
  // "Removed", "Removals", "Deprecated and Removed", "API changes": a category.
  // "`Cargo.lock` Removed from Tracking" (sqlx 0.9.0) is a news item about the
  // repository, and its three paragraphs were flagged breaking.
  // "Previously-deprecated APIs have been removed, including" (marshmallow 4) is a removal list, not a deprecation one.
  if (/(?:^\W*|(?:\band|[&/,])\s*)remov(?:e|ed|als?)\b|\bapi changes?\b|\b(?:have|has) been removed\b|\b(?:were|are) removed\b/i.test(heading)) return "removal";
  if (/security|vulnerab/i.test(heading)) return "security";
  if (/deprecat/i.test(heading)) return "deprecation";
  // Fixes are additive, and stricter: the author filed the entry as a bug fix, so API-shaped
  // wording in it ("change default export to named function") is not read as a break.
  if (FIX_HEADING.test(heading)) return "fixes";
  if (ADDITIVE_HEADING.test(heading)) return "additive";
  return null;
}

/** Final kind: an explicit heading or bullet parent wins; removal and additive contexts refine the line's wording. */
export function classifyEntry(raw: string, context: EntryContext | null): EntryKind {
  if (context === "breaking" || context === "security" || context === "deprecation") {
    // A security line under "Breaking" stays breaking: the heading is the author's own call.
    return context;
  }
  const text = classificationText(raw);
  if (context === "removal") {
    if (META_BREAKING.test(text)) return "change";
    if (EXPLICIT_BREAKING_MARKER.test(text)) return "breaking";
    if (STATED_COMPATIBLE.test(text) || UNDO.test(text)) return DEPRECATION.test(text) ? "deprecation" : "change";
    // A deprecation filed under Removed is one when it leads with it; "`x` (deprecated in 3.24.0)" was removed.
    if (LEADING_DEPRECATION.test(text) || (DEPRECATION.test(text) && !/\bremov|\(deprecated (?:in|since)\b|\bno longer\b|\bwere replaced\b/i.test(text))) {
      return "deprecation";
    }
    return isInternal(text) ? "change" : "breaking";
  }
  if (context === "additive" || context === "fixes") {
    if (!META_BREAKING.test(text) && EXPLICIT_BREAKING_MARKER.test(text)) return "breaking";
    // An API removal, rename or raised runtime minimum is breaking under "Features" too
    // (uuid 11 lists "remove UMD build" there; hyper 1.0 "rename to `Http2ClientConnExec`").
    const quiet = STATED_COMPATIBLE.test(text) || UNDO.test(text) || SCOPED_NON_API.test(text) || NON_BREAKING_LABEL.test(text);
    if (!quiet && !META_BREAKING.test(text)) {
      if (RUNTIME_SUPPORT.test(text)) return "breaking";
      if (context === "additive" && MADE_PRIVATE.test(text) && !LEADING_FIX.test(text)) return "breaking";
      if (context === "additive" && API_CHANGE.test(text) && !isInternal(text) && !LEADING_FIX.test(text)) return "breaking";
    }
    if (SECURITY.test(text)) return "security";
    return DEPRECATION.test(text) ? "deprecation" : "change";
  }
  return classifyText(text);
}
