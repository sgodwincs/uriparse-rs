use smol_str::SmolStr;
use std::ops::Deref;

/// A clone-on-write string container with
///
/// - `&str` for `Borrowed` case
/// - `SmolStr` for `Owned` case
#[derive(Debug, Clone)]
pub enum SmolStrCow<'s> {
    Borrowed(&'s str),
    Owned(SmolStr),
}

impl<'s> Deref for SmolStrCow<'s> {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(s) => *s,
            SmolStrCow::Owned(s) => s.deref(),
        }
    }
}

impl<'s> From<&'s str> for SmolStrCow<'s> {
    #[inline]
    fn from(v: &'s str) -> Self {
        Self::Borrowed(v)
    }
}

impl From<String> for SmolStrCow<'static> {
    #[inline]
    fn from(v: String) -> Self {
        Self::Owned(SmolStr::from(&v))
    }
}

impl From<SmolStr> for SmolStrCow<'static> {
    #[inline]
    fn from(v: SmolStr) -> Self {
        Self::Owned(v)
    }
}

impl<'s> SmolStrCow<'s> {
    /// Clone the data into an owned-type.
    #[inline]
    pub fn into_owned(&self) -> SmolStr {
        SmolStr::from(self.deref())
    }
}

/// serde Serialize implementation
#[cfg(feature = "serde")]
impl<'s> serde::Serialize for SmolStrCow<'s> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.deref())
    }
}

/// visitor for serde DeSerialize implementation
#[cfg(feature = "serde")]
struct SmolStrCowVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for SmolStrCowVisitor {
    type Value = SmolStrCow<'static>;

    #[inline]
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    #[inline]
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SmolStrCow::Owned(SmolStr::from(value)))
    }
}

#[cfg(feature = "serde")]
impl<'s, 'de> serde::Deserialize<'de> for SmolStrCow<'s> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(SmolStrCowVisitor)
    }
}
