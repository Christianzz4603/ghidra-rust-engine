//! Java archive (`.jar` / `.war` / `.zip` of class files) reader.
//!
//! Opens the archive, reads the manifest, and parses every `.class` entry with
//! [`crate::classfile`]. A class that fails to parse is recorded in [`Jar::failures`] instead of
//! aborting the whole archive, so one corrupt or unusual entry does not hide the rest.

use std::io::{Cursor, Read};
use std::path::Path;

use crate::classfile::ClassFile;
use crate::error::{Error, Result};

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("JAR: {}", message.into()))
}

/// Largest single archive entry that will be read (guards against decompression bombs).
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Main attributes of `META-INF/MANIFEST.MF`, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub attributes: Vec<(String, String)>,
}

impl Manifest {
    /// Parse the main section of a manifest. Continuation lines (starting with one space) are joined.
    pub fn parse(text: &str) -> Manifest {
        let mut attributes: Vec<(String, String)> = Vec::new();
        for raw in text.lines() {
            if raw.is_empty() {
                if !attributes.is_empty() {
                    break; // the main section ends at the first blank line
                }
                continue;
            }
            if let Some(rest) = raw.strip_prefix(' ') {
                if let Some((_, value)) = attributes.last_mut() {
                    value.push_str(rest);
                }
                continue;
            }
            if let Some((key, value)) = raw.split_once(':') {
                attributes.push((key.trim().to_string(), value.trim_start().to_string()));
            }
        }
        Manifest { attributes }
    }

    /// The value of an attribute (case-insensitive name), if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `Main-Class` attribute.
    pub fn main_class(&self) -> Option<&str> {
        self.get("Main-Class")
    }
}

/// A parsed archive.
#[derive(Clone, Debug)]
pub struct Jar {
    /// Every entry name, in archive order.
    pub entries: Vec<String>,
    pub manifest: Option<Manifest>,
    /// Successfully parsed classes as `(entry path, class)`.
    pub classes: Vec<(String, ClassFile)>,
    /// Class entries that could not be parsed, as `(entry path, reason)`.
    pub failures: Vec<(String, String)>,
}

impl Jar {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| fail(format!("cannot read archive: {e}")))?;
        Self::parse(bytes)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| fail(format!("invalid JAR/ZIP: {e}")))?;
        let mut jar = Jar {
            entries: Vec::new(),
            manifest: None,
            classes: Vec::new(),
            failures: Vec::new(),
        };
        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| fail(format!("ZIP entry error: {e}")))?;
            let name = file.name().to_string();
            jar.entries.push(name.clone());
            let is_class = name.ends_with(".class");
            let is_manifest = name.eq_ignore_ascii_case("META-INF/MANIFEST.MF");
            if !is_class && !is_manifest {
                continue;
            }
            let mut data = Vec::new();
            if let Err(e) = file.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut data) {
                jar.failures.push((name, format!("cannot read entry: {e}")));
                continue;
            }
            if data.len() as u64 > MAX_ENTRY_BYTES {
                jar.failures.push((name, "entry exceeds the size limit".to_string()));
                continue;
            }
            if is_manifest {
                jar.manifest = Some(Manifest::parse(&String::from_utf8_lossy(&data)));
            } else {
                match ClassFile::parse(&data) {
                    Ok(class) => jar.classes.push((name, class)),
                    Err(e) => jar.failures.push((name, e.to_string())),
                }
            }
        }
        if jar.classes.is_empty() && jar.failures.is_empty() {
            return Err(fail("archive contains no .class entries"));
        }
        Ok(jar)
    }

    /// Look up a parsed class by its internal name (`java/lang/Object`).
    pub fn class(&self, internal_name: &str) -> Option<&ClassFile> {
        self.classes
            .iter()
            .find(|(_, c)| c.this_class_name().is_ok_and(|n| n == internal_name))
            .map(|(_, c)| c)
    }

    /// A `javap -c -p`-style listing for every parsed class, as `(entry path, text)`.
    pub fn disassembly(&self) -> Vec<(String, Result<String>)> {
        self.classes
            .iter()
            .map(|(path, class)| (path.clone(), class.disassembly()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_continuations_and_stops_at_blank_line() {
        let text = "Manifest-Version: 1.0\r\nMain-Class: com.example.\r\n App\r\nCreated-By: x\r\n\r\nName: other\r\nFoo: bar\r\n";
        let m = Manifest::parse(text);
        assert_eq!(m.main_class(), Some("com.example.App"));
        assert_eq!(m.get("created-by"), Some("x"));
        assert_eq!(
            m.get("Foo"),
            None,
            "per-entry sections are not part of the main attributes"
        );
    }

    #[test]
    fn manifest_handles_empty_input() {
        assert_eq!(Manifest::parse("").attributes.len(), 0);
        assert_eq!(Manifest::parse("\n\nKey: v\n").get("Key"), Some("v"));
    }

    #[test]
    fn rejects_non_zip_bytes() {
        assert!(Jar::parse(vec![1, 2, 3, 4]).is_err());
    }
}
