//! Bounded duplicate-free JSON and JCS for this profile's string/object/array schemas.
use crate::{Error, MAX_HEADER};
use serde::{
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded string-schema JSON")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = vec![];
                while let Some(v) = a.next_element::<Unique>()? {
                    if out.len() >= 32 {
                        return Err(de::Error::custom("array bound"));
                    }
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.len() >= 32 || out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate key or object bound"));
                    }
                    out.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HEADER {
        return Err(Error::Bounds);
    }
    let value: Unique = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
    fn depth(v: &Value, n: usize) -> bool {
        n <= 8
            && match v {
                Value::Array(a) => a.iter().all(|v| depth(v, n + 1)),
                Value::Object(o) => o.values().all(|v| depth(v, n + 1)),
                _ => true,
            }
    }
    if !depth(&value.0, 0) {
        return Err(Error::Bounds);
    }
    serde_json::from_value(value.0).map_err(|_| Error::Malformed)
}
pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>, Error> {
    fn write(v: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
        match v {
            Value::String(s) => out.extend(serde_json::to_vec(s).map_err(|_| Error::Malformed)?),
            Value::Array(a) => {
                out.push(b'[');
                for (n, v) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    write(v, out)?;
                }
                out.push(b']');
            }
            Value::Object(o) => {
                let mut keys: Vec<_> = o.keys().collect();
                keys.sort_by_cached_key(|s| s.encode_utf16().collect::<Vec<_>>());
                out.push(b'{');
                for (n, k) in keys.into_iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(k).map_err(|_| Error::Malformed)?);
                    out.push(b':');
                    write(&o[k], out)?;
                }
                out.push(b'}');
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
    let mut out = vec![];
    write(value, &mut out)?;
    if out.len() > MAX_HEADER {
        return Err(Error::Bounds);
    }
    Ok(out)
}
