use std::path::Path;

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotlinDeclaration {
    pub kind: KotlinDeclarationKind,
    pub name: String,
    pub qualified_name: String,
    pub metadata_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KotlinDeclarationKind {
    Class,
    Function,
    Property,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotlinBuiltins {
    version: Vec<u32>,
    declarations: Vec<KotlinDeclaration>,
    raw_proto: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Varint(u64),
    Bytes(Vec<u8>),
}

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("Kotlin built-ins: {}", message.into()))
}

fn varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or_else(|| fail("truncated varint"))?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(fail("varint overflow"));
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(fail("invalid varint"))
}

fn fields(bytes: &[u8]) -> Result<Vec<(u32, Value)>> {
    let mut cursor = 0usize;
    let mut result = Vec::new();
    while cursor < bytes.len() {
        let key = varint(bytes, &mut cursor)?;
        let number = (key >> 3) as u32;
        if number == 0 {
            return Err(fail("protobuf field number zero"));
        }
        match key & 7 {
            0 => result.push((number, Value::Varint(varint(bytes, &mut cursor)?))),
            1 | 5 => {
                let width = if key & 7 == 1 { 8 } else { 4 };
                let end = cursor.checked_add(width).ok_or_else(|| fail("field overflow"))?;
                let data = bytes.get(cursor..end).ok_or_else(|| fail("truncated fixed-width field"))?;
                result.push((number, Value::Bytes(data.to_vec())));
                cursor = end;
            }
            2 => {
                let length = usize::try_from(varint(bytes, &mut cursor)?)
                    .map_err(|_| fail("field length overflow"))?;
                let end = cursor.checked_add(length).ok_or_else(|| fail("field overflow"))?;
                let data = bytes.get(cursor..end).ok_or_else(|| fail("truncated length-delimited field"))?;
                result.push((number, Value::Bytes(data.to_vec())));
                cursor = end;
            }
            wire => return Err(fail(format!("unsupported protobuf wire type {wire}"))),
        }
    }
    Ok(result)
}

fn bytes_field(items: &[(u32, Value)], number: u32) -> Vec<&[u8]> {
    items.iter().filter_map(|(field, value)| {
        if *field == number && let Value::Bytes(bytes) = value {
            return Some(bytes.as_slice());
        }
        None
    }).collect()
}

fn int_field(items: &[(u32, Value)], number: u32) -> Option<u32> {
    items.iter().find_map(|(field, value)| {
        if *field == number && let Value::Varint(value) = value {
            return u32::try_from(*value).ok();
        }
        None
    })
}

fn read_version(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u32>> {
    let count = *bytes.get(*cursor).ok_or_else(|| fail("missing metadata version"))? as usize;
    *cursor += 1;
    if count == 0 || count > 16 {
        return Err(fail("invalid metadata version length"));
    }
    let end = cursor.checked_add(count).ok_or_else(|| fail("version overflow"))?;
    let raw = bytes.get(*cursor..end).ok_or_else(|| fail("truncated metadata version"))?;
    *cursor = end;
    Ok(raw.iter().map(|value| *value as u32).collect())
}

fn resolve_qualified_name(
    index: u32,
    names: &[Vec<(u32, Value)>],
    strings: &[String],
    depth: usize,
) -> Result<String> {
    if depth > 128 {
        return Err(fail("qualified-name parent cycle"));
    }
    let entry = names.get(index as usize).ok_or_else(|| fail("qualified-name index out of range"))?;
    let short = int_field(entry, 2).ok_or_else(|| fail("qualified name has no short name"))?;
    let segment = strings.get(short as usize).ok_or_else(|| fail("qualified-name string index out of range"))?;
    let parent = int_field(entry, 1).unwrap_or(u32::MAX);
    if parent == u32::MAX {
        Ok(segment.clone())
    } else {
        Ok(format!("{}.{}", resolve_qualified_name(parent, names, strings, depth + 1)?, segment))
    }
}

impl KotlinBuiltins {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|error| fail(format!("cannot read {}: {error}", path.as_ref().display())))?;
        Self::parse(bytes)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let mut cursor = 0usize;
        let version = read_version(&bytes, &mut cursor)?;
        let raw_proto = bytes.get(cursor..).ok_or_else(|| fail("missing package fragment"))?.to_vec();
        if raw_proto.is_empty() {
            return Err(fail("missing package fragment protobuf"));
        }
        let fragment = fields(&raw_proto)?;
        let string_table_proto = bytes_field(&fragment, 1).into_iter().next()
            .ok_or_else(|| fail("package fragment has no string table"))?;
        let string_table_fields = fields(string_table_proto)?;
        let string_table = bytes_field(&string_table_fields, 1).into_iter()
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect::<Vec<_>>();
        let qualified_table_proto = bytes_field(&fragment, 2).into_iter().next()
            .ok_or_else(|| fail("package fragment has no qualified-name table"))?;
        let qualified_table_fields = fields(qualified_table_proto)?;
        let qualified_table = bytes_field(&qualified_table_fields, 1).into_iter()
            .map(fields)
            .collect::<Result<Vec<_>>>()?;

        let mut declarations = Vec::new();
        for class in bytes_field(&fragment, 4) {
            let class_fields = fields(class)?;
            let id = int_field(&class_fields, 3)
                .ok_or_else(|| fail("class has no qualified-name index"))?;
            let qualified_name = resolve_qualified_name(id, &qualified_table, &string_table, 0)?;
            let name = qualified_name.rsplit('.').next().unwrap_or(&qualified_name).to_string();
            declarations.push(KotlinDeclaration {
                kind: KotlinDeclarationKind::Class,
                name,
                qualified_name,
                metadata_index: id,
            });
        }

        if let Some(package) = bytes_field(&fragment, 3).into_iter().next() {
            let package_fields = fields(package)?;
            for (field_number, kind) in [
                (3, KotlinDeclarationKind::Function),
                (4, KotlinDeclarationKind::Property),
            ] {
                for declaration in bytes_field(&package_fields, field_number) {
                    let declaration_fields = fields(declaration)?;
                    if let Some(name_index) = int_field(&declaration_fields, 2)
                        && let Some(name) = string_table.get(name_index as usize)
                    {
                        declarations.push(KotlinDeclaration {
                            kind,
                            name: name.clone(),
                            qualified_name: name.clone(),
                            metadata_index: name_index,
                        });
                    }
                }
            }
        }

        Ok(Self { version, declarations, raw_proto })
    }

    pub fn version(&self) -> &[u32] {
        &self.version
    }

    pub fn declarations(&self) -> &[KotlinDeclaration] {
        &self.declarations
    }

    pub fn classes(&self) -> impl Iterator<Item = &KotlinDeclaration> {
        self.declarations.iter().filter(|item| item.kind == KotlinDeclarationKind::Class)
    }

    pub fn functions(&self) -> impl Iterator<Item = &KotlinDeclaration> {
        self.declarations.iter().filter(|item| item.kind == KotlinDeclarationKind::Function)
    }

    pub fn properties(&self) -> impl Iterator<Item = &KotlinDeclaration> {
        self.declarations.iter().filter(|item| item.kind == KotlinDeclarationKind::Property)
    }

    pub fn raw_proto(&self) -> &[u8] {
        &self.raw_proto
    }

    pub fn decompile(&self) -> String {
        let mut output = String::new();
        for declaration in &self.declarations {
            let keyword = match declaration.kind {
                KotlinDeclarationKind::Class => "class",
                KotlinDeclarationKind::Function => "fun",
                KotlinDeclarationKind::Property => "val",
            };
            output.push_str(&format!("{keyword} {}\n", declaration.qualified_name));
        }
        output
    }

    pub fn write_kotlin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| fail(format!("cannot create output directory: {error}")))?;
        }
        std::fs::write(path, self.decompile())
            .map_err(|error| fail(format!("cannot write Kotlin output: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_varint_fields() {
        assert_eq!(fields(&[0x08, 0x96, 0x01]).unwrap(), vec![(1, Value::Varint(150))]);
    }

    #[test]
    fn rejects_truncated_metadata() {
        assert!(KotlinBuiltins::parse(vec![]).is_err());
    }

    #[test]
    fn reads_metadata_version() {
        let mut cursor = 0;
        let version = read_version(&[3, 1, 0, 7], &mut cursor).unwrap();
        assert_eq!(version, vec![1, 0, 7]);
        assert_eq!(cursor, 4);
    }
}
