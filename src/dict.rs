//! FreeRADIUS-style dictionary parser.
//!
//! Implemented from scratch against the documented dictionary file format
//! (see `NOTICE.md`). The parser understands the directives actually used by
//! the RADIUS dictionaries: `ATTRIBUTE`, `VALUE`, `VENDOR`, `BEGIN-VENDOR`,
//! `END-VENDOR`, `BEGIN-TLV`, `END-TLV` and `$INCLUDE`. Unknown directives are
//! ignored so that extended dictionaries remain loadable.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// RADIUS attribute data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    String,
    Octets,
    Integer,
    Integer64,
    IpAddr,
    Ipv4Prefix,
    Ipv6Addr,
    Ipv6Prefix,
    Ifid,
    Date,
    Abinary,
    Byte,
    Short,
    Signed,
    Ether,
    Tlv,
    ComboIp,
    Evs,
    Extended,
    LongExtended,
    Vsa,
    Bool,
    Unknown,
}

impl DataType {
    /// Parse a dictionary type token, tolerating an `octets[N]` fixed length
    /// suffix and mixed casing.
    pub fn parse(token: &str) -> DataType {
        let base = token
            .split('[')
            .next()
            .unwrap_or(token)
            .to_ascii_lowercase();
        match base.as_str() {
            "string" => DataType::String,
            "octets" => DataType::Octets,
            "integer" => DataType::Integer,
            "integer64" => DataType::Integer64,
            "ipaddr" => DataType::IpAddr,
            "ipv4prefix" => DataType::Ipv4Prefix,
            "ipv6addr" => DataType::Ipv6Addr,
            "ipv6prefix" => DataType::Ipv6Prefix,
            "ifid" => DataType::Ifid,
            "date" => DataType::Date,
            "abinary" => DataType::Abinary,
            "byte" => DataType::Byte,
            "short" => DataType::Short,
            "signed" => DataType::Signed,
            "ether" => DataType::Ether,
            "tlv" => DataType::Tlv,
            "combo-ip" => DataType::ComboIp,
            "evs" => DataType::Evs,
            "extended" => DataType::Extended,
            "long-extended" => DataType::LongExtended,
            "vsa" => DataType::Vsa,
            "bool" => DataType::Bool,
            _ => DataType::Unknown,
        }
    }

    /// True for types whose encoded payload is an integer.
    pub fn is_integer_like(&self) -> bool {
        matches!(
            self,
            DataType::Integer
                | DataType::Byte
                | DataType::Short
                | DataType::Signed
                | DataType::Date
        )
    }
}

/// Per-attribute behaviour flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttrFlags {
    /// `encrypt=N`; 0 means no encryption.
    pub encrypt: u8,
    pub has_tag: bool,
    pub concat: bool,
    pub virtual_flag: bool,
    pub internal: bool,
    pub array: bool,
}

/// A single named enum value of an attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
}

/// One dictionary attribute.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    /// Top-level RADIUS attribute type (the first path component).
    pub number: u32,
    /// Full numeric path. For plain attributes this is `[number]`; for nested
    /// TLV / RFC 6929 extended attributes it is e.g. `[186, 11, 2, 1]`.
    pub path: Vec<u32>,
    pub ty: DataType,
    /// Vendor ID, or 0 for a standard (non-VSA) attribute.
    pub vendor: u32,
    pub flags: AttrFlags,
    /// Name of the enclosing TLV attribute, if any.
    pub parent_tlv: Option<String>,
    pub values: Vec<EnumValue>,
    value_by_name: HashMap<String, i64>,
    name_by_value: HashMap<i64, String>,
}

impl Attribute {
    /// The RFC 6929 extended-type octet, if this is an extended attribute.
    pub fn extended(&self) -> Option<u32> {
        self.path.get(1).copied()
    }

    fn add_value(&mut self, name: String, value: i64) {
        self.value_by_name.insert(name.clone(), value);
        self.name_by_value.entry(value).or_insert(name.clone());
        self.values.push(EnumValue { name, value });
    }

    /// Resolve an enum name to its numeric value.
    pub fn value_of(&self, name: &str) -> Option<i64> {
        self.value_by_name.get(name).copied()
    }

    /// Resolve a numeric value to its enum name.
    pub fn name_of(&self, value: i64) -> Option<&str> {
        self.name_by_value.get(&value).map(|s| s.as_str())
    }
}

/// Wire layout of vendor-specific attributes for a vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorFormat {
    /// Bytes used for the vendor attribute type (usually 1).
    pub type_len: u8,
    /// Bytes used for the vendor attribute length (usually 1).
    pub length_len: u8,
    /// Vendor attributes may be continued across multiple VSAs.
    pub continuation: bool,
}

impl Default for VendorFormat {
    fn default() -> Self {
        VendorFormat {
            type_len: 1,
            length_len: 1,
            continuation: false,
        }
    }
}

/// A registered vendor.
#[derive(Debug, Clone)]
pub struct Vendor {
    pub name: String,
    pub id: u32,
    pub format: VendorFormat,
}

/// A parsed dictionary.
#[derive(Debug, Default)]
pub struct Dictionary {
    pub attrs: Vec<Attribute>,
    by_name: HashMap<String, usize>,
    by_key: HashMap<(u32, u32), usize>,
    by_path: HashMap<(u32, Vec<u32>), usize>,
    pub vendors: Vec<Vendor>,
    vendor_by_name: HashMap<String, usize>,
    vendor_by_id: HashMap<u32, usize>,
    tlv_children: HashMap<usize, Vec<usize>>,
}

impl Dictionary {
    pub fn attr_by_name(&self, name: &str) -> Option<&Attribute> {
        self.by_name.get(name).map(|&i| &self.attrs[i])
    }

    pub fn attr_by_key(&self, vendor: u32, number: u32) -> Option<&Attribute> {
        self.by_key.get(&(vendor, number)).map(|&i| &self.attrs[i])
    }

    /// Look up an attribute by its full numeric path (supports nested TLV and
    /// RFC 6929 extended attributes).
    pub fn attr_by_path(&self, vendor: u32, path: &[u32]) -> Option<&Attribute> {
        self.by_path
            .get(&(vendor, path.to_vec()))
            .map(|&i| &self.attrs[i])
    }

    pub fn vendor_by_name(&self, name: &str) -> Option<&Vendor> {
        self.vendor_by_name
            .get(name)
            .and_then(|&i| self.vendors.get(i))
    }

    pub fn vendor_by_id(&self, id: u32) -> Option<&Vendor> {
        self.vendor_by_id
            .get(&id)
            .and_then(|&i| self.vendors.get(i))
    }

    /// Vendor wire format for an ID, falling back to the RADIUS default.
    pub fn vendor_format(&self, id: u32) -> VendorFormat {
        self.vendor_by_id(id).map(|v| v.format).unwrap_or_default()
    }

    pub fn tlv_children(&self, parent_index: usize) -> &[usize] {
        self.tlv_children
            .get(&parent_index)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Load `<dir>/dictionary` and everything it includes.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Dictionary, DictError> {
        let main = dir.as_ref().join("dictionary");
        Self::load_file(&main)
    }

    /// Load a specific dictionary file.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Dictionary, DictError> {
        let mut parser = Parser::new();
        parser.parse_file(path.as_ref())?;
        parser.finish()
    }

    pub fn attribute_count(&self) -> usize {
        self.attrs.len()
    }
}

/// Dictionary loading error.
#[derive(Debug)]
pub struct DictError {
    pub message: String,
}

impl fmt::Display for DictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DictError {}

impl DictError {
    fn new(message: impl Into<String>) -> Self {
        DictError {
            message: message.into(),
        }
    }
}

/// Pending `VALUE` record resolved after all files are parsed.
struct PendingValue {
    attr: String,
    name: String,
    value: i64,
}

struct Parser {
    dict: Dictionary,
    current_vendor: u32,
    current_tlv: Option<String>,
    pending_values: Vec<PendingValue>,
    visited: HashSet<PathBuf>,
    unknown_directives: HashMap<String, u64>,
}

impl Parser {
    fn new() -> Self {
        Parser {
            dict: Dictionary::default(),
            current_vendor: 0,
            current_tlv: None,
            pending_values: Vec::new(),
            visited: HashSet::new(),
            unknown_directives: HashMap::new(),
        }
    }

    fn parse_file(&mut self, path: &Path) -> Result<(), DictError> {
        let canonical = fs::canonicalize(path).map_err(|e| {
            DictError::new(format!("cannot open dictionary {}: {e}", path.display()))
        })?;
        if !self.visited.insert(canonical.clone()) {
            return Ok(()); // already parsed (also breaks include cycles)
        }
        let text = fs::read_to_string(&canonical).map_err(|e| {
            DictError::new(format!(
                "cannot read dictionary {}: {e}",
                canonical.display()
            ))
        })?;
        let base_dir = canonical
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();

        for (lineno, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let directive = tokens[0];
            let result = match directive {
                "$INCLUDE" => self.directive_include(&tokens, &base_dir),
                "ATTRIBUTE" => self.directive_attribute(&tokens),
                "VALUE" => self.directive_value(&tokens),
                "VENDOR" => self.directive_vendor(&tokens),
                "BEGIN-VENDOR" => {
                    self.directive_begin_vendor(&tokens);
                    Ok(())
                }
                "END-VENDOR" => {
                    self.current_vendor = 0;
                    Ok(())
                }
                "BEGIN-TLV" => {
                    if tokens.len() >= 2 {
                        self.current_tlv = Some(tokens[1].to_string());
                    }
                    Ok(())
                }
                "END-TLV" => {
                    self.current_tlv = None;
                    Ok(())
                }
                other => {
                    *self
                        .unknown_directives
                        .entry(other.to_string())
                        .or_insert(0) += 1;
                    Ok(())
                }
            };
            result.map_err(|e| {
                DictError::new(format!(
                    "{}:{}: {}",
                    canonical.display(),
                    lineno + 1,
                    e.message
                ))
            })?;
        }
        Ok(())
    }

    fn directive_include(&mut self, tokens: &[&str], base_dir: &Path) -> Result<(), DictError> {
        let Some(name) = tokens.get(1) else {
            return Err(DictError::new("$INCLUDE requires a file name"));
        };
        let candidate = Path::new(name);
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            base_dir.join(candidate)
        };
        self.parse_file(&resolved)
    }

    fn directive_attribute(&mut self, tokens: &[&str]) -> Result<(), DictError> {
        if tokens.len() < 4 {
            return Err(DictError::new("ATTRIBUTE requires name, number and type"));
        }
        let name = tokens[1].to_string();
        let path = parse_path(tokens[2])
            .ok_or_else(|| DictError::new(format!("invalid attribute number '{}'", tokens[2])))?;
        let number = path[0];
        let ty = DataType::parse(tokens[3]);

        let mut flags = AttrFlags::default();
        let mut vendor = self.current_vendor;
        for flag in &tokens[4..] {
            if let Some(rest) = flag.strip_prefix("encrypt=") {
                flags.encrypt = rest.parse().unwrap_or(0);
            } else if let Some(rest) = flag.strip_prefix("vendor=") {
                if let Some(&idx) = self.dict.vendor_by_name.get(rest) {
                    vendor = self.dict.vendors[idx].id;
                }
            } else {
                match *flag {
                    "has_tag" => flags.has_tag = true,
                    "concat" => flags.concat = true,
                    "virtual" => flags.virtual_flag = true,
                    "internal" => flags.internal = true,
                    "array" => flags.array = true,
                    _ => {}
                }
            }
        }

        self.insert_attribute(Attribute {
            name,
            number,
            path,
            ty,
            vendor,
            flags,
            parent_tlv: self.current_tlv.clone(),
            values: Vec::new(),
            value_by_name: HashMap::new(),
            name_by_value: HashMap::new(),
        });
        Ok(())
    }

    fn insert_attribute(&mut self, attr: Attribute) {
        let name = attr.name.clone();
        let vendor = attr.vendor;
        let path = attr.path.clone();
        let index = self.dict.attrs.len();
        // Only a top-level attribute can be resolved by (vendor, type); nested
        // attributes share the top-level type and are keyed by full path.
        if path.len() == 1 {
            self.dict.by_key.insert((vendor, path[0]), index);
        }
        self.dict.by_path.insert((vendor, path), index);
        self.dict.attrs.push(attr);
        self.dict.by_name.insert(name, index);
    }

    fn directive_value(&mut self, tokens: &[&str]) -> Result<(), DictError> {
        if tokens.len() < 4 {
            return Err(DictError::new("VALUE requires attribute, name and number"));
        }
        let value = parse_number(tokens[3])
            .ok_or_else(|| DictError::new(format!("invalid VALUE number '{}'", tokens[3])))?;
        self.pending_values.push(PendingValue {
            attr: tokens[1].to_string(),
            name: tokens[2].to_string(),
            value,
        });
        Ok(())
    }

    fn directive_vendor(&mut self, tokens: &[&str]) -> Result<(), DictError> {
        if tokens.len() < 3 {
            return Err(DictError::new("VENDOR requires a name and an id"));
        }
        let name = tokens[1].to_string();
        let id = parse_number(tokens[2])
            .ok_or_else(|| DictError::new(format!("invalid vendor id '{}'", tokens[2])))?
            as u32;
        let mut format = VendorFormat::default();
        for flag in &tokens[3..] {
            if let Some(spec) = flag.strip_prefix("format=") {
                format = parse_vendor_format(spec);
            }
        }
        let index = self.dict.vendors.len();
        self.dict.vendors.push(Vendor {
            name: name.clone(),
            id,
            format,
        });
        self.dict.vendor_by_name.insert(name, index);
        self.dict.vendor_by_id.insert(id, index);
        Ok(())
    }

    fn directive_begin_vendor(&mut self, tokens: &[&str]) {
        if let Some(name) = tokens.get(1) {
            if let Some(&idx) = self.dict.vendor_by_name.get(*name) {
                self.current_vendor = self.dict.vendors[idx].id;
            } else {
                self.current_vendor = 0;
            }
        }
    }

    fn finish(mut self) -> Result<Dictionary, DictError> {
        // Resolve enum values now that every attribute is known.
        let pending = std::mem::take(&mut self.pending_values);
        for pv in pending {
            if let Some(&idx) = self.dict.by_name.get(&pv.attr) {
                self.dict.attrs[idx].add_value(pv.name, pv.value);
            }
            // Values for undefined attributes are ignored, matching lenient
            // loading of extended dictionaries.
        }
        // Build TLV parent -> children index.
        for (idx, attr) in self.dict.attrs.iter().enumerate() {
            if let Some(parent) = &attr.parent_tlv {
                if let Some(&p) = self.dict.by_name.get(parent) {
                    self.dict.tlv_children.entry(p).or_default().push(idx);
                }
            }
        }
        Ok(self.dict)
    }
}

/// Remove a `#` comment, keeping the code part.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse a decimal or `0x` hexadecimal number.
fn parse_number(token: &str) -> Option<i64> {
    let t = token.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<i64>().ok()
    }
}

/// Parse a dotted numeric attribute path such as `186.11.2.1`.
fn parse_path(token: &str) -> Option<Vec<u32>> {
    let mut path = Vec::new();
    for part in token.split('.') {
        let value = parse_number(part)?;
        if !(0..=u32::MAX as i64).contains(&value) {
            return None;
        }
        path.push(value as u32);
    }
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Parse a `format=T,L[,c]` vendor specification.
fn parse_vendor_format(spec: &str) -> VendorFormat {
    let mut parts = spec.split(',');
    let type_len = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let length_len = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let continuation = parts.next().map(|s| s.trim() == "c").unwrap_or(false);
    VendorFormat {
        type_len,
        length_len,
        continuation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_str(text: &str) -> Dictionary {
        let mut file = tempfile::Builder::new().suffix(".dict").tempfile().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file.flush().unwrap();
        Dictionary::load_file(file.path()).unwrap()
    }

    #[test]
    fn parses_standard_attribute_and_value() {
        let d = parse_str(
            "ATTRIBUTE\tUser-Name\t1\tstring\n\
             ATTRIBUTE\tService-Type\t6\tinteger\n\
             VALUE\tService-Type\tLogin-User\t1\n\
             VALUE\tService-Type\tFramed-User\t2\n",
        );
        let un = d.attr_by_name("User-Name").unwrap();
        assert_eq!(un.number, 1);
        assert_eq!(un.ty, DataType::String);
        let st = d.attr_by_name("Service-Type").unwrap();
        assert_eq!(st.value_of("Framed-User"), Some(2));
        assert_eq!(st.name_of(1), Some("Login-User"));
    }

    #[test]
    fn parses_vendor_and_vendor_attributes() {
        let d = parse_str(
            "VENDOR\tCisco\t9\n\
             BEGIN-VENDOR\tCisco\n\
             ATTRIBUTE\tCisco-AVPair\t1\tstring\n\
             ATTRIBUTE\tCisco-NAS-Port\t2\tstring\tencrypt=1\n\
             END-VENDOR\tCisco\n",
        );
        let v = d.vendor_by_name("Cisco").unwrap();
        assert_eq!(v.id, 9);
        let a = d.attr_by_name("Cisco-AVPair").unwrap();
        assert_eq!(a.vendor, 9);
        assert_eq!(a.number, 1);
        assert_eq!(d.attr_by_key(9, 2).unwrap().flags.encrypt, 1);
        // Standard namespace untouched.
        assert!(d.attr_by_key(0, 1).is_none());
    }

    #[test]
    fn parses_vendor_format() {
        let d = parse_str("VENDOR\tWiMAX\t24757\tformat=2,1,c\n");
        let v = d.vendor_by_name("WiMAX").unwrap();
        assert_eq!(
            v.format,
            VendorFormat {
                type_len: 2,
                length_len: 1,
                continuation: true
            }
        );
    }

    #[test]
    fn parses_tlv_children() {
        let d = parse_str(
            "ATTRIBUTE\tParent\t1\ttlv\n\
             BEGIN-TLV\tParent\n\
             ATTRIBUTE\tChild-A\t1\tstring\n\
             ATTRIBUTE\tChild-B\t2\tinteger\n\
             END-TLV\tParent\n",
        );
        let parent = d.attr_by_name("Parent").unwrap();
        assert_eq!(parent.ty, DataType::Tlv);
        let parent_idx = d.by_name["Parent"];
        let kids: Vec<&str> = d
            .tlv_children(parent_idx)
            .iter()
            .map(|&i| d.attrs[i].name.as_str())
            .collect();
        assert_eq!(kids, vec!["Child-A", "Child-B"]);
        assert_eq!(
            d.attr_by_name("Child-A").unwrap().parent_tlv.as_deref(),
            Some("Parent")
        );
    }

    #[test]
    fn strips_comments_and_tolerates_unknown_directives() {
        let d = parse_str(
            "# leading comment\n\
             ATTRIBUTE\tFoo\t1\tstring # trailing\n\
             FLAGS\tSomething\n\
             \n",
        );
        assert_eq!(d.attribute_count(), 1);
        assert!(d.attr_by_name("Foo").is_some());
    }

    #[test]
    fn parses_nested_tlv_path() {
        let d = parse_str(
            "ATTRIBUTE\tParent\t186\ttlv\n\
             ATTRIBUTE\tChild\t186.11\ttlv\n\
             ATTRIBUTE\tLeaf\t186.11.2\tinteger\n",
        );
        let leaf = d.attr_by_name("Leaf").unwrap();
        assert_eq!(leaf.number, 186);
        assert_eq!(leaf.path, vec![186, 11, 2]);
        assert_eq!(leaf.extended(), Some(11));
        assert!(d.attr_by_path(0, &[186, 11, 2]).is_some());
        // Nested attributes must not shadow the top-level type lookup.
        assert_eq!(d.attr_by_key(0, 186).unwrap().name, "Parent");
    }

    #[test]
    fn follows_includes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("dictionary"),
            "$INCLUDE dictionary.inner\nATTRIBUTE\tOuter\t200\tinteger\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("dictionary.inner"),
            "ATTRIBUTE\tInner\t100\tstring\n",
        )
        .unwrap();
        let d = Dictionary::load_dir(dir.path()).unwrap();
        assert!(d.attr_by_name("Inner").is_some());
        assert!(d.attr_by_name("Outer").is_some());
    }
}
