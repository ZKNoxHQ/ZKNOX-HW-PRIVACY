//! Error type. Messages are copied verbatim from the TypeScript so that both
//! implementations can be compared on the failure path too.

use std::fmt;

/// An error carrying the same message string as the TypeScript `throw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl Error {
    /// Builds an error from anything displayable.
    pub fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Shorthand for building an [`Error`].
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::error::Error(format!($($arg)*))
    };
}
