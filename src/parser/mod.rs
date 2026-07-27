//! SQL classification and hint parsing module (`parser`)
//!
//! Handles SQL read/write classification, hint comment parsing, and
//! analytics pattern matching.

pub mod classifier;
pub mod hint;
pub mod pattern;

pub use classifier::{Classifier, KeywordClassifier, SqlKind};
pub use hint::{HintParser, RegexHintParser, RouteHint};
pub use pattern::{PatternMatcher, RegexPatternMatcher};
