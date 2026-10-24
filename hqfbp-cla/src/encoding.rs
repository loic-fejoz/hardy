//! HQFBP content encoding configuration, serde serialization, and dynamic selector engine.

use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

#[cfg(feature = "serde")]
use std::fmt;

pub use hqfbp_rs::ContentEncoding;

use hardy_bpv7::bundle::Id;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

/// Parses a comma-separated or space-separated list of encoding strings, respecting parenthesized arguments.
///
/// # Errors
/// Returns an error string if any of the tokenized encodings cannot be parsed.
pub fn parse_encodings_from_str(s: &str) -> core::result::Result<Vec<ContentEncoding>, String> {
    let mut list = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;

    for ch in s.chars() {
        match ch {
            '(' => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' | ';' if paren_depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    let enc = ContentEncoding::try_from(trimmed).map_err(|e| e.to_string())?;
                    list.push(enc);
                }
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        let enc = ContentEncoding::try_from(trimmed).map_err(|e| e.to_string())?;
        list.push(enc);
    }
    Ok(list)
}

/// Dynamic encoding selector contract allowing on-the-fly customization of bundle encodings.
pub trait DynamicEncodingSelector: Send + Sync {
    /// Determines the encoding pipeline for an outgoing bundle.
    fn select_encodings(
        &self,
        destination: Option<&str>,
        lane: Option<u32>,
        bundle_id: &Id,
        total_len: u64,
        default_encodings: &[ContentEncoding],
    ) -> Vec<ContentEncoding>;
}

/// Default dynamic encoding selector that prioritizes registered peer encodings,
/// then lane-specific overrides, falling back to the configured default encodings.
#[derive(Debug, Default, Clone)]
pub struct DefaultEncodingSelector {
    lane_encodings: HashMap<u32, Vec<ContentEncoding>>,
}

impl DefaultEncodingSelector {
    /// Creates a new default selector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Associates a specific encoding pipeline with a bundle transmission lane.
    pub fn with_lane_encoding(mut self, lane: u32, encodings: Vec<ContentEncoding>) -> Self {
        self.lane_encodings.insert(lane, encodings);
        self
    }
}

impl DynamicEncodingSelector for DefaultEncodingSelector {
    fn select_encodings(
        &self,
        _destination: Option<&str>,
        lane: Option<u32>,
        _bundle_id: &Id,
        _total_len: u64,
        default_encodings: &[ContentEncoding],
    ) -> Vec<ContentEncoding> {
        if let Some(l) = lane
            && let Some(lane_encs) = self.lane_encodings.get(&l)
        {
            return lane_encs.clone();
        }
        default_encodings.to_vec()
    }
}

/// Serde helper module for encoding and decoding lists of [`ContentEncoding`].
#[cfg(feature = "serde")]
pub mod serde_encodings {
    use super::*;

    /// Serializes a slice of [`ContentEncoding`] into a vector of strings.
    pub fn serialize<S>(
        encodings: &[ContentEncoding],
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = encodings.iter().map(ToString::to_string).collect();
        strings.serialize(serializer)
    }

    /// Deserializes a list of [`ContentEncoding`] from either a YAML sequence of strings or a single comma-separated string.
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<Vec<ContentEncoding>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EncodingsVisitor;

        impl<'de> Visitor<'de> for EncodingsVisitor {
            type Value = Vec<ContentEncoding>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .write_str("a sequence of encoding strings or a single comma-separated string")
            }

            fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_encodings_from_str(v).map_err(serde::de::Error::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut list = Vec::new();
                while let Some(item) = seq.next_element::<String>()? {
                    let enc = ContentEncoding::try_from(item.as_str())
                        .map_err(serde::de::Error::custom)?;
                    list.push(enc);
                }
                Ok(list)
            }
        }

        deserializer.deserialize_any(EncodingsVisitor)
    }
}

/// Serde helper module for optional lists of [`ContentEncoding`].
#[cfg(feature = "serde")]
pub mod serde_option_encodings {
    use super::*;

    /// Serializes an optional list of [`ContentEncoding`].
    pub fn serialize<S>(
        encodings: &Option<Vec<ContentEncoding>>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match encodings {
            Some(list) => serde_encodings::serialize(list, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional list of [`ContentEncoding`].
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<Option<Vec<ContentEncoding>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Helper(#[serde(with = "serde_encodings")] Vec<ContentEncoding>);

        Option::<Helper>::deserialize(deserializer).map(|opt| opt.map(|h| h.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_encodings_from_str() {
        let encs = parse_encodings_from_str("gzip, h, rs(255, 223), crc32").unwrap();
        assert_eq!(encs.len(), 4);
        assert_eq!(encs[0], ContentEncoding::Gzip);
        assert_eq!(encs[1], ContentEncoding::H);
        assert_eq!(encs[2], ContentEncoding::ReedSolomon(255, 223));
        assert_eq!(encs[3], ContentEncoding::Crc32);
    }

    #[test]
    fn test_default_selector_lane_fallback() {
        let default_encs = vec![ContentEncoding::H, ContentEncoding::Crc32];
        let lane1_encs = vec![
            ContentEncoding::Gzip,
            ContentEncoding::H,
            ContentEncoding::ReedSolomon(255, 200),
        ];

        let selector = DefaultEncodingSelector::new().with_lane_encoding(1, lane1_encs.clone());
        let bundle_id = Id::default();

        let res_lane0 = selector.select_encodings(None, Some(0), &bundle_id, 100, &default_encs);
        assert_eq!(res_lane0, default_encs);

        let res_lane1 = selector.select_encodings(None, Some(1), &bundle_id, 100, &default_encs);
        assert_eq!(res_lane1, lane1_encs);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_encodings_roundtrip_sequence() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Container {
            #[serde(with = "serde_encodings")]
            encs: Vec<ContentEncoding>,
        }

        let orig = Container {
            encs: vec![
                ContentEncoding::Gzip,
                ContentEncoding::H,
                ContentEncoding::ReedSolomon(255, 223),
            ],
        };

        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"encs":["gzip","h","rs(255,223)"]}"#);

        let parsed: Container = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, orig);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_encodings_from_comma_separated_string() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Container {
            #[serde(with = "serde_encodings")]
            encs: Vec<ContentEncoding>,
        }

        let json = r#"{"encs":"gzip, h, crc32"}"#;
        let parsed: Container = serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed.encs,
            vec![
                ContentEncoding::Gzip,
                ContentEncoding::H,
                ContentEncoding::Crc32
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_option_encodings_roundtrip() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Container {
            #[serde(default, with = "serde_option_encodings")]
            encs: Option<Vec<ContentEncoding>>,
        }

        let some_container = Container {
            encs: Some(vec![ContentEncoding::H, ContentEncoding::Crc32]),
        };
        let json_some = serde_json::to_string(&some_container).unwrap();
        assert_eq!(json_some, r#"{"encs":["h","crc32"]}"#);
        let parsed_some: Container = serde_json::from_str(&json_some).unwrap();
        assert_eq!(parsed_some, some_container);

        let none_container = Container { encs: None };
        let json_none = serde_json::to_string(&none_container).unwrap();
        assert_eq!(json_none, r#"{"encs":null}"#);
        let parsed_none: Container = serde_json::from_str(&json_none).unwrap();
        assert_eq!(parsed_none, none_container);

        let parsed_empty: Container = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed_empty, none_container);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_invalid_encoding_fails() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Container {
            #[serde(with = "serde_encodings")]
            encs: Vec<ContentEncoding>,
        }

        let json_bad = r#"{"encs":["rs(10,20)"]}"#; // invalid RS params: k >= n
        let err = serde_json::from_str::<Container>(json_bad).unwrap_err();
        assert!(!err.to_string().is_empty());

        let json_bad_str = r#"{"encs":"rs(10,20)"}"#;
        assert!(serde_json::from_str::<Container>(json_bad_str).is_err());

        let json_bad_type = r#"{"encs":12345}"#;
        let err_type = serde_json::from_str::<Container>(json_bad_type).unwrap_err();
        assert!(
            err_type
                .to_string()
                .contains("a sequence of encoding strings")
        );
    }
}
