use core::fmt;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StacksStringError;

impl fmt::Display for StacksStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Stacks string")
    }
}

impl std::error::Error for StacksStringError {}

/// printable-ASCII-only string, but encodable.
/// Note that it cannot be longer than ARRAY_MAX_LEN (4.1 billion bytes)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksString(Vec<u8>);

impl fmt::Display for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(self).into_owned().as_str())
    }
}

impl fmt::Debug for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(self).into_owned().as_str())
    }
}

impl Deref for StacksString {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for StacksString {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl StacksString {
    /// Is the given string a valid Clarity string?
    pub fn is_valid_string(s: &String) -> bool {
        s.is_ascii() && StacksString::is_printable(s)
    }

    pub fn is_printable(s: &String) -> bool {
        if !s.is_ascii() {
            return false;
        }
        // all characters must be ASCII "printable" characters, excluding "delete".
        // This is 0x20 through 0x7e, inclusive, as well as '\t' and '\n'
        // TODO: DRY up with vm::representations
        for c in s.as_bytes().iter() {
            if (*c < 0x20 && *c != b'\t' && *c != b'\n') || *c > 0x7e {
                return false;
            }
        }
        true
    }

    pub fn from_string(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_string(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn try_from_str(s: &str) -> Option<StacksString> {
        if !StacksString::is_valid_string(&String::from(s)) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    // TODO: migrate callers to `str::parse`, `TryFrom<&str>`, or `try_from_str`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<StacksString> {
        Self::try_from_str(s)
    }
}

impl FromStr for StacksString {
    type Err = StacksStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StacksString::try_from_str(s).ok_or(StacksStringError)
    }
}

impl TryFrom<&str> for StacksString {
    type Error = StacksStringError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for StacksString {
    type Error = StacksStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::StacksString;

    #[test]
    fn rejects_non_printable_strings() {
        assert!(StacksString::try_from_str("hello\rworld").is_none());
        assert!(StacksString::try_from_str("hello\x01world").is_none());
        assert!(StacksString::try_from_str("hello\x7fworld").is_none());
        assert!(StacksString::try_from_str("héllo").is_none());
    }

    #[test]
    fn accepts_tab_and_newline() {
        assert!(StacksString::try_from_str("line1\nline2").is_some());
        assert!(StacksString::try_from_str("col1\tcol2").is_some());
    }

    #[test]
    fn printable_ascii_boundaries() {
        assert!(StacksString::try_from_str(" ").is_some());
        assert!(StacksString::try_from_str("~").is_some());
        let below_printable = String::from_utf8(vec![0x1f]).unwrap();
        assert!(StacksString::from_string(&below_printable).is_none());
        let delete = String::from_utf8(vec![0x7f]).unwrap();
        assert!(StacksString::from_string(&delete).is_none());
    }
}
