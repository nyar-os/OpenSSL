use core::fmt;

use data_binary_asn1::{DerError, DerErrorKind, DerResult, Oid, Reader, Tag, encode_element};

/// One attribute inside an RDN: an OID and its printable value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
    /// The attribute type OID.
    pub oid: Oid,
    /// The attribute value decoded to text when possible.
    pub value: String,
}

/// A distinguished name: a sequence of RDNs plus the raw DER for exact linkage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    raw: Vec<u8>,
    rdns: Vec<Vec<AttributeTypeAndValue>>,
}

impl Name {
    /// Parse a `Name` (SEQUENCE OF RDN) and keep the raw element bytes.
    pub fn parse(reader: &mut Reader<'_>) -> DerResult<Self> {
        let element = reader.expect(Tag::SEQUENCE)?;
        let raw = encode_element(element.tag, element.value);
        let mut rdns = Vec::new();
        let mut outer = element.reader();
        while !outer.is_empty() {
            let set = outer.expect(Tag::SET)?;
            let mut inner = set.reader();
            let mut items = Vec::new();
            while !inner.is_empty() {
                let mut atv = inner.expect_sequence()?;
                let oid = atv.expect_oid()?;
                let value_element = atv.read_tlv()?;
                let value = match value_element.tag {
                    Tag::UTF8_STRING | Tag::PRINTABLE_STRING | Tag::IA5_STRING => inner.text_of(value_element)?,
                    _ => return Err(DerError::new(DerErrorKind::MalformedContent, value_element.offset)),
                };
                items.push(AttributeTypeAndValue { oid, value: value.to_string() });
            }
            rdns.push(items);
        }
        Ok(Self { raw, rdns })
    }

    /// The raw DER encoding, used for exact issuer-to-subject linkage.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The parsed RDN sequence.
    pub fn rdns(&self) -> &[Vec<AttributeTypeAndValue>] {
        &self.rdns
    }

    /// The first commonName value, if any.
    pub fn common_name(&self) -> Option<&str> {
        let oid = data_binary_asn1::oids::common_name();
        self.rdns.iter().flatten().find(|item| item.oid == oid).map(|item| item.value.as_str())
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for rdn in self.rdns.iter().rev() {
            for item in rdn {
                if !first {
                    formatter.write_str(", ")?;
                }
                first = false;
                write!(formatter, "{}={}", short_type(&item.oid), item.value)?;
            }
        }
        Ok(())
    }
}

fn short_type(oid: &Oid) -> &'static str {
    let dotted = oid.dotted();
    match dotted.as_str() {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        _ => "OID",
    }
}
