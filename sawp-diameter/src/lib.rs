//! Protocol References:
//!     https://tools.ietf.org/html/rfc6733
//!     https://tools.ietf.org/html/rfc4072
//!     https://tools.ietf.org/html/rfc4187
//!     https://tools.ietf.org/html/rfc3748

// #[macro_use]
//extern crate num_derive;

use sawp::error::{Error, NomError, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;

use nom::bytes::streaming::tag;
use nom::bytes::streaming::take;
use nom::combinator;
use nom::error::ErrorKind;
use nom::multi::many0;
use nom::number::streaming::{be_u16, be_u24, be_u32, be_u64, be_u8};
use nom::IResult;

use bytestream::*;
use std::io::*;

use bitflags::bitflags;
use byteorder::WriteBytesExt;
use num_enum::TryFromPrimitive;
use sawp::error::ErrorKind::InvalidData;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use EapAkaAttributeTypeCode::*;

#[derive(Debug)]
pub struct Diameter {}

#[derive(Debug, PartialEq)]
pub struct Header {
    version: u8,
    length: u32,
    // Actually u24
    flags: u8,
    code: u32,
    // Actually u24
    app_id: u32,
    hop_id: u32,
    end_id: u32,
}

/// AVP Attribute Names as stated in the [protocol reference](https://tools.ietf.org/html/rfc6733#section-4.5)
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum AttributeCode {
    Unknown = 0,
    AcctInterimInterval = 85,
    AccountingRealtimeRequired = 483,
    AcctMultiSessionId = 50,
    AccountingRecordNumber = 485,
    AccountingRecordType = 480,
    AcctSessionId = 44,
    AccountingSubSessionId = 287,
    AcctApplicationId = 259,
    AuthApplicationId = 258,
    AuthRequestType = 274,
    AuthorizationLifetime = 291,
    AuthGracePeriod = 276,
    AuthSessionState = 277,
    ReAuthRequestType = 285,
    Class = 25,
    DestinationHost = 293,
    DestinationRealm = 283,
    DisconnectCause = 273,
    EapPayLoad = 462,
    ErrorMessage = 281,
    ErrorReportingHost = 294,
    EventTimestamp = 55,
    ExperimentalResult = 297,
    ExperimentalResultCode = 298,
    FailedAVP = 279,
    FirmwareRevision = 267,
    HostIPAddress = 257,
    InbandSecurityId = 299,
    MultiRoundTimeOut = 272,
    OriginHost = 264,
    OriginRealm = 296,
    OriginStateId = 278,
    ProductName = 269,
    ProxyHost = 280,
    ProxyInfo = 284,
    ProxyState = 33,
    RedirectHost = 292,
    RedirectHostUsage = 261,
    RedirectMaxCacheTime = 262,
    ResultCode = 268,
    RouteRecord = 282,
    SessionId = 263,
    SessionTimeout = 27,
    SessionBinding = 270,
    SessionServerFailover = 271,
    SupportedVendorId = 265,
    TerminationCause = 295,
    UserName = 1,
    VendorId = 266,
    VendorSpecificApplicationId = 260,
}

#[derive(Debug, PartialEq)]
pub struct Attribute {
    /// Value of the code in AVP header
    raw: u32,
    /// Attribute name associated with raw value
    code: AttributeCode,
}

impl Attribute {
    pub fn new(val: u32) -> Self {
        Attribute {
            raw: val,
            code: AttributeCode::try_from(val).unwrap_or(AttributeCode::Unknown),
        }
    }
}

/// AVP Data Format as specified in the [protocol reference](https://tools.ietf.org/html/rfc6733#section-4.2)
#[derive(Debug, PartialEq)]
pub enum Value {
    Unhandled(Vec<u8>),
    OctetString(Vec<u8>),
    Integer32(i32),
    Integer64(i64),
    Unsigned32(u32),
    Unsigned64(u64),
    Float32(f32),
    Float64(f64),
    Grouped(Vec<AVP>),
    Enumerated(u32),
    UTF8String(String),
    DiameterIdentity(String),
    DiameterURI(String),
    Address(IpAddr),
    Time(u32),
    Eap(EapPayload),
}

impl Value {
    pub fn new<'a>(code: &AttributeCode, data: &'a [u8]) -> IResult<&'a [u8], (Self, ErrorFlags)> {
        match code {
            AttributeCode::AcctSessionId | AttributeCode::ProxyState => {
                Ok((&[], (Value::OctetString(data.into()), ErrorFlags::NONE)))
            }
            AttributeCode::EapPayLoad => {
                let (data, raw_code) = be_u8(data)?;
                let (data, identifier) = be_u8(data)?;
                let (data, length) = be_u16(data)?;
                let (data, raw_type) = be_u8(data)?;

                match EapPayloadType::new(raw_type).code {
                    EapPayloadTypeCode::Identity => match String::from_utf8(data.to_vec()) {
                        Ok(id) => {
                            let eap_payload = EapPayload {
                                code: EapPayloadCode::new(raw_code),
                                identifier,
                                length,
                                payload_type: EapPayloadType::new(raw_type),
                                type_data: TypeData::Identity(id),
                            };
                            Ok((&[], (Value::Eap(eap_payload), ErrorFlags::NONE)))
                        }
                        Err(_) => {
                            Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE)))
                        }
                    },
                    EapPayloadTypeCode::Aka => {
                        return match Self::handle_eap_aka(
                            raw_code, identifier, length, raw_type, data,
                        ) {
                            Ok(eap_payload) => Ok(eap_payload),
                            Err(_) => {
                                Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE)))
                            }
                        };
                    }
                    EapPayloadTypeCode::Unknown => {
                        Ok((&[], (Value::OctetString(data.into()), ErrorFlags::NONE)))
                    }
                }
            }
            AttributeCode::AcctInterimInterval
            | AttributeCode::AccountingRecordNumber
            | AttributeCode::AcctApplicationId
            | AttributeCode::AuthApplicationId
            | AttributeCode::AuthorizationLifetime
            | AttributeCode::AuthGracePeriod
            | AttributeCode::ExperimentalResultCode
            | AttributeCode::FirmwareRevision
            | AttributeCode::InbandSecurityId
            | AttributeCode::MultiRoundTimeOut
            | AttributeCode::OriginStateId
            | AttributeCode::RedirectMaxCacheTime
            | AttributeCode::ResultCode
            | AttributeCode::SessionTimeout
            | AttributeCode::SessionBinding
            | AttributeCode::SupportedVendorId
            | AttributeCode::VendorId => {
                let (input, val) = be_u32(data)?;
                Ok((input, (Value::Unsigned32(val), ErrorFlags::NONE)))
            }
            AttributeCode::AccountingSubSessionId => {
                let (input, val) = be_u64(data)?;
                Ok((input, (Value::Unsigned64(val), ErrorFlags::NONE)))
            }
            AttributeCode::AccountingRealtimeRequired
            | AttributeCode::AccountingRecordType
            | AttributeCode::AuthRequestType
            | AttributeCode::AuthSessionState
            | AttributeCode::ReAuthRequestType
            | AttributeCode::DisconnectCause
            | AttributeCode::RedirectHostUsage
            | AttributeCode::SessionServerFailover
            | AttributeCode::TerminationCause => {
                let (input, val) = be_u32(data)?;
                Ok((input, (Value::Enumerated(val), ErrorFlags::NONE)))
            }
            AttributeCode::ExperimentalResult
            | AttributeCode::FailedAVP
            | AttributeCode::ProxyInfo
            | AttributeCode::VendorSpecificApplicationId => {
                let (input, (avps, error_flags)) = parse_avps(data)?;
                Ok((input, (Value::Grouped(avps), error_flags)))
            }
            AttributeCode::AcctMultiSessionId
            | AttributeCode::Class
            | AttributeCode::ErrorMessage
            | AttributeCode::ProductName
            | AttributeCode::SessionId
            | AttributeCode::UserName => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::UTF8String(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::DestinationHost
            | AttributeCode::DestinationRealm
            | AttributeCode::ErrorReportingHost
            | AttributeCode::OriginHost
            | AttributeCode::OriginRealm
            | AttributeCode::ProxyHost
            | AttributeCode::RouteRecord => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::DiameterIdentity(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::RedirectHost => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::DiameterURI(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::HostIPAddress => match data.len() {
                4 => Ok((
                    &[],
                    (
                        // unwrap shouldn't panic, since we check length
                        Value::Address(IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(data).unwrap(),
                        ))),
                        ErrorFlags::NONE,
                    ),
                )),
                16 => Ok((
                    &[],
                    (
                        // unwrap shouldn't panic, since we check length
                        Value::Address(IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(data).unwrap(),
                        ))),
                        ErrorFlags::NONE,
                    ),
                )),
                _ => Ok((
                    &[],
                    (Value::Unhandled(data.into()), ErrorFlags::DATA_LENGTH),
                )),
            },
            AttributeCode::EventTimestamp => {
                let (input, seconds) = be_u32(data)?;
                Ok((input, (Value::Time(seconds), ErrorFlags::NONE)))
            }
            _ => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::NONE))),
        }
    }

    fn handle_eap_aka(
        raw_code: u8,
        identifier: u8,
        length: u16,
        raw_type: u8,
        data: &[u8],
    ) -> Result<(&[u8], (Value, ErrorFlags))> {
        let (data, raw_sub_type) = be_u8(data)?;
        let (data, reserved) = be_u16(data)?;
        let sub_type = EapAkaSubType::new(raw_sub_type);

        let mut error_flags = ErrorFlags::NONE;
        let mut attributes = Vec::new();
        let (rest, attrs) = many0(combinator::complete(EapAkaAttribute::parse))(data)?;

        debug_assert_eq!(rest.len(), 0);
        for (attribute, flag) in attrs {
            error_flags |= flag;
            attributes.push(attribute)
        }
        let eap_payload = EapPayload {
            code: EapPayloadCode::new(raw_code),
            identifier,
            length,
            payload_type: EapPayloadType::new(raw_type),
            type_data: TypeData::EapAka(EapAkaTypeData {
                sub_type,
                reserved,
                attrs: attributes,
            }),
        };

        Ok((&[], (Value::Eap(eap_payload), error_flags)))
    }
}

#[derive(Debug, PartialEq)]
pub struct AVP {
    attribute: Attribute,
    flags: u8,
    length: u32,
    // Actually u24
    vendor_id: Option<u32>,
    value: Value,
    padding: Vec<u8>,
}

bitflags! {
    /// Flags identify messages which parse successfully
    /// but contain invalid data. The caller can use the message's
    /// error flags to see if and what errors were in the
    /// pack of bytes and take action using this information.
    pub struct ErrorFlags: u8 {
        const NONE = 0b0000_0000;
        const DATA_VALUE = 0b0000_0001;
        const DATA_LENGTH = 0b0000_0010;
        const NON_ZERO_RESERVED = 0b0000_0100;
        const NON_ZERO_PADDING = 0b0000_1000;
    }
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub avps: Vec<AVP>,
    pub error_flags: ErrorFlags,
}

/// Create a parser to read diameter length and ensure input is long enough
/// # Arguments
/// * `read` - How many bytes of length have already been read
///
fn length(read: usize) -> impl Fn(&[u8]) -> IResult<&[u8], u32> {
    move |input: &[u8]| {
        let (input, length) = be_u24(input)?;
        let len = length as usize;
        if len < read {
            Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::LengthValue,
            )))
        } else if len > (input.len() + read) {
            Err(nom::Err::Incomplete(nom::Needed::new(
                len - (input.len() + read),
            )))
        } else {
            Ok((input, length))
        }
    }
}

impl Header {
    const SIZE: usize = 20;
    // Number of bytes included in length that are before and
    // including the length field
    const PRE_LENGTH_SIZE: usize = 4;

    // Flags
    pub const REQUEST_FLAG: u8 = 0b1000_0000;
    pub const PROXIABLE_FLAG: u8 = 0b0100_0000;
    pub const ERROR_FLAG: u8 = 0b0010_0000;
    pub const POTENTIALLY_RETRANSMITTED_FLAG: u8 = 0b0001_0000;
    pub const RESERVED_MASK: u8 = 0b0000_1111;

    fn reserved_set(flags: u8) -> bool {
        flags & Self::RESERVED_MASK != 0
    }

    ///  If set, the message is a request.  If cleared, the message is
    /// an answer.
    pub fn is_request(&self) -> bool {
        self.flags & Self::REQUEST_FLAG != 0
    }

    /// If set, the message MAY be proxied, relayed, or redirected.  If
    /// cleared, the message MUST be locally processed.
    pub fn is_proxiable(&self) -> bool {
        self.flags & Self::PROXIABLE_FLAG != 0
    }

    /// If set, the message contains a protocol error, and the message
    /// will not conform to the CCF described for this command.
    /// Messages with the 'E' bit set are commonly referred to as error
    /// messages.  This bit MUST NOT be set in request messages
    pub fn is_error(&self) -> bool {
        self.flags & Self::ERROR_FLAG != 0
    }

    /// This flag is set after a link failover procedure, to aid the
    /// removal of duplicate requests.  It is set when resending
    /// requests not yet acknowledged, as an indication of a possible
    /// duplicate due to a link failure.
    pub fn is_potentially_retransmitted(&self) -> bool {
        self.flags & Self::POTENTIALLY_RETRANSMITTED_FLAG != 0
    }

    /// These flag bits are reserved for future use; they MUST be set
    /// to zero and ignored by the receiver.
    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    /// Length of AVPs
    pub fn length(&self) -> usize {
        (self.length as usize) - Self::SIZE
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], (Self, ErrorFlags)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, version) = tag(&[1u8])(input)?;
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        if (length as usize) < Self::SIZE {
            return Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::LengthValue,
            )));
        }
        let (input, flags) = be_u8(input)?;
        if Self::reserved_set(flags) {
            error_flags |= ErrorFlags::NON_ZERO_RESERVED;
        }
        let (input, code) = be_u24(input)?;
        let (input, app_id) = be_u32(input)?;
        let (input, hop_id) = be_u32(input)?;
        let (input, end_id) = be_u32(input)?;

        Ok((
            input,
            (
                Self {
                    version: version[0],
                    length,
                    flags,
                    code,
                    app_id,
                    hop_id,
                    end_id,
                },
                error_flags,
            ),
        ))
    }
}

impl AVP {
    // Number of bytes included in length that are before and
    // including the length field
    const PRE_LENGTH_SIZE: usize = 8;

    // Flags
    pub const VENDOR_SPECIFIC_FLAG: u8 = 0b1000_0000;
    pub const MANDATORY_FLAG: u8 = 0b0100_0000;
    pub const PROTECTED_FLAG: u8 = 0b0010_0000;
    pub const RESERVED_MASK: u8 = 0b0001_1111;

    fn vendor_specific_flag(flags: u8) -> bool {
        flags & Self::VENDOR_SPECIFIC_FLAG != 0
    }

    fn reserved_set(flags: u8) -> bool {
        flags & Self::RESERVED_MASK != 0
    }

    fn padding(length: usize) -> usize {
        match length % 4 {
            0 => 0,
            n => 4 - n,
        }
    }

    /// The 'V' bit, known as the Vendor-Specific bit, indicates whether
    /// the optional Vendor-ID field is present in the AVP header.  When
    /// set, the AVP Code belongs to the specific vendor code address
    /// space.
    pub fn is_vendor_specific(&self) -> bool {
        Self::vendor_specific_flag(self.flags)
    }

    /// The 'M' bit, known as the Mandatory bit, indicates whether the
    /// receiver of the AVP MUST parse and understand the semantics of the
    /// AVP including its content.
    pub fn is_mandatory(&self) -> bool {
        self.flags & Self::MANDATORY_FLAG != 0
    }

    /// The 'P' bit, known as the Protected bit, has been reserved for
    /// future usage of end-to-end security
    pub fn is_protected(&self) -> bool {
        self.flags & Self::PROTECTED_FLAG != 0
    }

    /// The sender of the AVP MUST set 'R' (reserved) bits to 0 and the
    /// receiver SHOULD ignore all 'R' (reserved) bits.
    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], (Self, ErrorFlags)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, raw_code) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        if Self::reserved_set(flags) {
            error_flags |= ErrorFlags::NON_ZERO_RESERVED;
        }
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        let header_size = if Self::vendor_specific_flag(flags) {
            Self::PRE_LENGTH_SIZE + 4
        } else {
            Self::PRE_LENGTH_SIZE
        };
        if (length as usize) < header_size {
            return Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::LengthValue,
            )));
        }
        let data_length = (length as usize) - header_size;
        let (input, vendor_id) = if Self::vendor_specific_flag(flags) {
            let (input, v) = be_u32(input)?;
            (input, Some(v))
        } else {
            (input, None)
        };

        let (input, data) = take(data_length)(input)?;
        let (input, padding) = take(Self::padding(data_length))(input)?;
        if !padding.iter().all(|&item| item == 0) {
            error_flags |= ErrorFlags::NON_ZERO_PADDING;
        }
        let attribute = Attribute::new(raw_code);
        let value = match Value::new(&attribute.code, data) {
            Ok((rest, (value, flags))) => {
                if !rest.is_empty() {
                    error_flags |= ErrorFlags::DATA_LENGTH;
                }
                error_flags |= flags;
                value
            }
            Err(nom::Err::Error(NomError {
                                    input: _,
                                    code: ErrorKind::LengthValue,
                                }))
            | Err(nom::Err::Incomplete(_)) => {
                error_flags |= ErrorFlags::DATA_LENGTH;
                Value::Unhandled(data.into())
            }
            Err(_) => {
                error_flags |= ErrorFlags::DATA_VALUE;
                Value::Unhandled(data.into())
            }
        };

        Ok((
            input,
            (
                Self {
                    attribute,
                    flags,
                    length,
                    vendor_id,
                    value,
                    padding: padding.into(),
                },
                error_flags,
            ),
        ))
    }
}

impl std::fmt::Display for ErrorFlags {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl Protocol<'_> for Diameter {
    type Message = Message;

    fn name() -> &'static str {
        "diameter"
    }
}

#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EapPayloadCodeCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct EapPayloadCode {
    raw: u8,
    code: EapPayloadCodeCode,
}

impl EapPayloadCode {
    fn new(id: u8) -> Self {
        EapPayloadCode {
            raw: id,
            code: EapPayloadCodeCode::try_from(id).unwrap_or(EapPayloadCodeCode::Unknown),
        }
    }
}

#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EapPayloadTypeCode {
    Identity = 1,
    Aka = 23,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct EapPayloadType {
    raw: u8,
    code: EapPayloadTypeCode,
}

impl EapPayloadType {
    fn new(id: u8) -> Self {
        EapPayloadType {
            raw: id,
            code: EapPayloadTypeCode::try_from(id).unwrap_or(EapPayloadTypeCode::Unknown),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TypeData {
    Identity(String),
    EapAka(EapAkaTypeData),
}

#[derive(Debug, PartialEq)]
pub struct EapPayload {
    pub code: EapPayloadCode,
    pub identifier: u8,
    // must be same in request and (corresponding) requests
    pub length: u16,
    // the entire payload, including type data
    pub payload_type: EapPayloadType,
    pub type_data: TypeData,
}

// https://datatracker.ietf.org/doc/html/rfc4187#section-11
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EapAkaSubTypeCode {
    AkaChallenge = 1,
    AkaAuthenticationReject = 2,
    AkaIdentity = 5,
    SimStart = 10,
    SimChallenge = 11,
    AkaNotificationAndSimNotification = 12,
    AkaReauthenticationAndSimReauthentication = 13,
    AkeClientErrorAndSimClientError = 14,
    UnKnown,
}

#[derive(Debug, PartialEq)]
pub struct EapAkaSubType {
    raw: u8,
    code: EapAkaSubTypeCode,
}

impl EapAkaSubType {
    pub fn new(id: u8) -> Self {
        EapAkaSubType {
            raw: id,
            code: EapAkaSubTypeCode::try_from(id).unwrap_or(EapAkaSubTypeCode::UnKnown),
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc4187#section-11
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EapAkaAttributeTypeCode {
    AtRand = 1,
    AtAutn = 2,
    AtRes = 3,
    AtAuts = 4,
    AtPadding = 6,
    AtNonceMt = 7,
    AtPermanentIdReq = 10,
    AtMac = 11,
    AtNotification = 12,
    AtAnyIdReq = 13,
    AtIdentity = 14,
    AtVersionList = 15,
    AtSelectedVersion = 16,
    AtFullAuthIdReq = 17,
    AtCounter = 19,
    AtCounterTooSmall = 20,
    AtNonceS = 21,
    AtClientErrorCode = 22,
    AtIv = 129,
    AtEncData = 130,
    AtNextPseudonym = 132,
    AtNextReauthId = 133,
    AtCheckCode = 134,
    AtResultInd = 135,
    UnKnown,
}

#[derive(Debug, PartialEq)]
pub struct EapAkaAttributeType {
    pub raw: u8,
    pub code: EapAkaAttributeTypeCode,
}

impl EapAkaAttributeType {
    pub fn new(id: u8) -> Self {
        EapAkaAttributeType {
            raw: id,
            code: EapAkaAttributeTypeCode::try_from(id).unwrap_or(UnKnown),
        }
    }
}

impl StreamWriter for EapAkaAttributeType {
    fn write_to<W: Write>(&self, buffer: &mut W, order: ByteOrder) -> std::io::Result<()> {
        self.raw.write_to(buffer, order)?;
        Ok(())
    }
}


#[derive(Debug, PartialEq)]
pub enum EapAkaAttributeValue {
    NoValue,
    AtVecValue(u16, Vec<u8>),
    AtIdentityValue(u16, String),
    U16(u16),
    Unknown,
}

impl EapAkaAttributeValue {
    pub fn len_val_vec(&self) -> Option<(&u16, &Vec<u8>)> {
        match self {
            EapAkaAttributeValue::AtVecValue(len, val) => Some((len, val)),
            _ => None,
        }
    }

    pub fn len_val_str(&self) -> Option<(&u16, &str)> {
        match self {
            EapAkaAttributeValue::AtIdentityValue(len, str) => Some((len, str)),
            _ => None,
        }
    }
}

impl StreamWriter for EapAkaAttributeValue {
    fn write_to<W: Write>(&self, buffer: &mut W, order: ByteOrder) -> std::io::Result<()> {
        return match self {
            EapAkaAttributeValue::AtVecValue(aux, data) => {
                aux.write_to(buffer, order)?;
                buffer.write_all(data.as_slice())?;
                Ok(())
            }
            EapAkaAttributeValue::AtIdentityValue(aux, data) => {
                aux.write_to(buffer, order)?;
                buffer.write_all(data.as_bytes())?;
                Ok(())
            }
            EapAkaAttributeValue::U16(attr) => {
                attr.write_to(buffer, order)?;
                Ok(())
            }
            EapAkaAttributeValue::NoValue => {
                0u16.write_to(buffer, order)?;
                Ok(())
            }
            EapAkaAttributeValue::Unknown => Ok(()),
        };
    }
}

// https://datatracker.ietf.org/doc/html/rfc4187#page-48
#[derive(Debug, PartialEq)]
pub struct EapAkaAttribute {
    pub attribute_type: EapAkaAttributeType,
    pub length: u8,
    // in multiple of 4 bytes
    // pub value: Vec<u8>,
    pub value: EapAkaAttributeValue,
}

impl EapAkaAttribute {
    fn new(
        attribute_type_code: EapAkaAttributeTypeCode,
        value: EapAkaAttributeValue,
    ) -> Result<Self> {
        match attribute_type_code {
            AtRand | AtAutn | AtIv | AtPadding | AtMac | AtNonceS => match value {
                EapAkaAttributeValue::AtVecValue(len, data) => {
                    if data.len() == 16 {
                        return Ok(EapAkaAttribute {
                            attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                            length: 5,
                            value: EapAkaAttributeValue::AtVecValue(len, data),
                        });
                    }
                    Err(Error::incomplete_needed(16usize))
                }
                _ => Err(Error::from(InvalidData)),
            },
            AtRes | AtIdentity | AtNextPseudonym | AtNextReauthId => match value {
                EapAkaAttributeValue::AtVecValue(len, mut data) => {
                    sanitize_data_len(len, &data, &attribute_type_code)?;

                    let desired_len = ((3 + data.len()) / 4) * 4;
                    // extend buffer
                    if desired_len != data.len() {
                        data.resize(desired_len, 0);
                    }
                    return Ok(EapAkaAttribute {
                        attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                        length: (4usize + data.len() / 4usize) as u8,
                        value: EapAkaAttributeValue::AtVecValue(len, data),
                    });
                }
                _ => Err(Error::from(InvalidData)),
            },
            AtAuts => match value {
                EapAkaAttributeValue::AtVecValue(_len, data) => {
                    sanitize_data_len(0, &data, &attribute_type_code)?;
                    return Ok(EapAkaAttribute {
                        attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                        length: 4,
                        value: EapAkaAttributeValue::AtVecValue(14, data), // replace with value?
                    });
                }
                _ => Err(Error::from(InvalidData)),
            },
            AtResultInd | AtCounterTooSmall | AtFullAuthIdReq | AtPermanentIdReq | AtAnyIdReq => {
                match value {
                    EapAkaAttributeValue::NoValue => {
                        return Ok(EapAkaAttribute {
                            attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                            length: 1,
                            value,
                        });
                    }
                    _ => Err(Error::from(InvalidData)),
                }
            }
            AtCounter | AtClientErrorCode => match value {
                EapAkaAttributeValue::U16(_val) => {
                    return Ok(EapAkaAttribute {
                        attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                        length: 1,
                        value,
                    });
                }
                _ => Err(Error::from(InvalidData)),
            },
            AtCheckCode => match value {
                EapAkaAttributeValue::AtVecValue(_aux, data) => {
                    sanitize_data_len(0, &data, &attribute_type_code)?;
                    return Ok(EapAkaAttribute {
                        attribute_type: EapAkaAttributeType::new(attribute_type_code as u8),
                        length: 1 + (data.len() / 4) as u8,
                        value: EapAkaAttributeValue::AtVecValue(0, data),
                    });
                }
                _ => Err(Error::from(InvalidData)),
            },
            AtEncData | AtNonceMt | AtNotification | AtVersionList | AtSelectedVersion
            | UnKnown => Err(Error::from(InvalidData)),
        }
    }

    fn parse(input: &[u8]) -> IResult<&[u8], (Self, ErrorFlags)> {
        let (input, raw_eap_aka_att_type) = be_u8(input)?;
        let attribute_type = EapAkaAttributeType::new(raw_eap_aka_att_type);
        let (input, length) = be_u8(input)?;
        let mut remaining: &[u8] = &[];

        let value: EapAkaAttributeValue = match attribute_type.code {
            AtPermanentIdReq | AtAnyIdReq | AtFullAuthIdReq => {
                assert_eq!(length, 1);
                EapAkaAttributeValue::NoValue
            }
            AtIdentity => {
                let (input, actual_identity_length) = be_u16(input)?;
                let (input, val) = take(actual_identity_length)(input)?;
                remaining = input;
                match String::from_utf8(val.to_vec()) {
                    Ok(val) => EapAkaAttributeValue::AtIdentityValue(actual_identity_length, val),
                    Err(_) => {
                        // error_flags |= ErrorFlags::DATA_VALUE;
                        // Value::Unhandled(input.into())
                        EapAkaAttributeValue::Unknown
                    }
                }
            }
            AtRand | AtAutn | AtMac | AtIv | AtNonceS => {
                let (input, reserved) = be_u16(input)?;
                let (input, val) = take(16usize)(input)?;
                // debug_assert_eq!(input.len(), 0);
                debug_assert_eq!(reserved, 0);
                debug_assert_eq!(length, 5);
                remaining = input;
                EapAkaAttributeValue::AtVecValue(reserved, val.to_vec())
            }
            AtRes => {
                let (input, res_length) = be_u16(input)?;
                let content_len = ((length - 1) * 4) as usize;
                let (input, val) = take(content_len)(input)?;
                debug_assert!(res_length >= 32 && res_length <= 128);
                debug_assert_eq!(content_len, (res_length / 8) as usize);
                // debug_assert_eq!(input.len(), 0);
                remaining = input;
                EapAkaAttributeValue::AtVecValue(res_length, val.to_vec())
            }
            AtAuts | AtPadding | AtNonceMt | AtNotification | AtVersionList | AtSelectedVersion
            | AtCounter | AtCounterTooSmall | AtClientErrorCode | AtEncData | AtNextPseudonym
            | AtNextReauthId | AtCheckCode | AtResultInd | UnKnown => EapAkaAttributeValue::Unknown,
        };
        Ok((
            remaining,
            (
                EapAkaAttribute {
                    attribute_type,
                    length,
                    value,
                },
                ErrorFlags::NONE,
            ),
        ))
    }
}

impl StreamWriter for EapAkaAttribute {
    fn write_to<W: Write>(&self, buffer: &mut W, order: ByteOrder) -> std::io::Result<()> {
        self.attribute_type.write_to(buffer, order)?;
        self.length.write_to(buffer, order)?;
        self.value.write_to(buffer, order)?;
        Ok(())
    }
}

fn sanitize_data_len(
    aux: u16,
    data: &Vec<u8>,
    att_type_code: &EapAkaAttributeTypeCode,
) -> Result<u8> {
    match att_type_code {
        AtRes => {
            if (aux / 8) as usize <= data.len() {
                return Ok(0);
            }
        }
        AtIdentity | AtNextPseudonym | AtNextReauthId => {
            if aux as usize == data.len() {
                return Ok(0);
            }
        }
        AtRand | AtAutn | AtIv | AtEncData | AtPadding | AtMac | AtNonceS => {
            if aux == 0 && data.len() == 4 {
                return Ok(0);
            }
        }
        AtAuts => {
            if data.len() == 14 {
                return Ok(0);
            }
        }
        _ => {}
    }
    Err(Error::from(InvalidData))
}

#[derive(Debug, PartialEq)]
pub struct EapAkaTypeData {
    pub sub_type: EapAkaSubType,
    pub reserved: u16,
    pub attrs: Vec<EapAkaAttribute>,
}

fn parse_avps(input: &[u8]) -> IResult<&[u8], (Vec<AVP>, ErrorFlags)> {
    let (rest, avps_flags) = many0(combinator::complete(AVP::parse))(input)?;
    if !rest.is_empty() {
        // many0 will stop if sub-parser fails, but should read all
        Err(nom::Err::Error(NomError::new(input, ErrorKind::Many0)))
    } else {
        let mut error_flags = ErrorFlags::NONE;
        let mut avps = Vec::new();
        for (avp, flag) in avps_flags {
            error_flags |= flag;
            avps.push(avp)
        }

        Ok((rest, (avps, error_flags)))
    }
}

impl<'a> Parse<'a> for Diameter {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, (header, flags)) = Header::parse(input)?;
        error_flags |= flags;

        // Don't have to worry about splitting slice causing incomplete
        // Because we have verified the length in Header::parse
        let (input, avps_input) = combinator::complete(take(header.length()))(input)?;
        let (_, (avps, flags)) = parse_avps(avps_input)?;
        error_flags |= flags;
        Ok((
            input,
            Some(Message {
                header,
                avps,
                error_flags,
            }),
        ))
    }
}

impl<'a> Probe<'a> for Diameter {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytestream::ByteOrder::BigEndian;
    use rstest::rstest;
    use sawp::probe::Status;

    #[test]
    fn foo() {
        let e1 = EapPayloadType::new(1);
        assert_eq!(e1.code, EapPayloadTypeCode::Identity);
        println!("{:?}", e1);
    }

    #[test]
    fn test_name() {
        assert_eq!(Diameter::name(), "diameter");
    }

    #[rstest(
    input,
    expected,
    case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::new(1)))),
    case::hello_world(b"hello world", Err(nom::Err::Error(NomError::new(b"hello world" as & [u8], ErrorKind::Tag)))),
    case::invalid_length(
    & [
    // Version: 1
    0x01,
    // Length: 12
    0x00, 0x00, 0x0c,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Err(nom::Err::Error(NomError::new(
    & [
    // Flags: 128 (Request)
    0x80_u8,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ] as & [u8],
    ErrorKind::LengthValue))
    )
    ),
    case::diagnostic(
    & [
    // Version: 1
    0x01,
    // Length: 20
    0x00, 0x00, 0x14,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Ok((& [] as & [u8],
    (
    Header {
    version: 1,
    length: 20,
    flags: 128,
    code: 257,
    app_id: 0,
    hop_id: 0x53ca_fe6a,
    end_id: 0x7dc0_a11b,
    },
    ErrorFlags::NONE,
    )))
    ),
    case::reserved_set(
    & [
    // Version: 1
    0x01,
    // Length: 20
    0x00, 0x00, 0x14,
    // Flags: 128 (Request)
    0x0f,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Ok((& [] as & [u8],
    (
    Header {
    version: 1,
    length: 20,
    flags: 15,
    code: 257,
    app_id: 0,
    hop_id: 0x53ca_fe6a,
    end_id: 0x7dc0_a11b,
    },
    ErrorFlags::NON_ZERO_RESERVED,
    )))
    ),
    case::diagnostic(
    & [
    // Version: 1
    0x01,
    // Length: 24
    0x00, 0x00, 0x18,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Err(nom::Err::Incomplete(nom::Needed::new(4)))
    ),
    )]
    fn test_header(input: &[u8], expected: IResult<&[u8], (Header, ErrorFlags)>) {
        let h = Header::parse(input);
        assert_eq!(h, expected);
    }

    #[test]
    fn test_parse_at_rand_short() {
        let input = &[
            0x01, 0x05, 0x00, 0x00, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x72, 0x61,
            0x6e, 0x64, 0x6f, 0x6d,
        ];

        match EapAkaAttribute::parse(input) {
            Ok(_attr) => {
                panic!("This should not work, not enough data")
            }
            Err(_err) => {
                assert!(true);
            }
        }
    }

    #[test]
    fn test_parse_at_res_short() {
        let input = &[
            0x03, 0x05, 0x00, 0x80, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x61, 0x62, 0x63, 0x64,
        ];

        match EapAkaAttribute::parse(input) {
            Ok(_attr) => {
                panic!("This should not work, not enough data")
            }
            Err(_err) => {
                assert!(true);
            }
        }
    }

    #[test]
    fn test_serialize() {
        let input: &[u8] = &[
            0x0b, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let attr = EapAkaAttribute::parse(input).unwrap().1.0;
        let mut buf = Vec::<u8>::new();
        let res = attr.write_to(&mut buf, BigEndian);
        println!("{:?}", buf);
        let attr = EapAkaAttribute::parse(buf.as_slice()).unwrap().1.0;
        println!("{:?}", attr);

        let attr = EapAkaAttribute::new(
            AtAnyIdReq,
            EapAkaAttributeValue::NoValue,
        ).unwrap();
        let mut buf = Vec::<u8>::new();
        let res = attr.write_to(&mut buf, BigEndian);
        println!("{:?}", buf);
        let attr = EapAkaAttribute::parse(buf.as_slice()).unwrap().1.0;
        println!("{:?}", attr);
    }

    #[rstest(
    input,
    expected,
    case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::new(1)))),
    case::atrand(
    & [
    0x01, 0x05, 0x00, 0x00, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x2e, 0x2e,
    ],
    Ok((& [] as & [u8],
    (
    EapAkaAttribute {
    attribute_type: EapAkaAttributeType {
    raw: 1,
    code: AtRand,
    },
    length: 5,
    value: EapAkaAttributeValue::AtVecValue(0x00, vec ! [0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x2e, 0x2e, ]),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::atres(
    & [
    0x03, 0x05, 0x00, 0x80, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    ],
    Ok((& [] as & [u8],
    (
    EapAkaAttribute {
    attribute_type: EapAkaAttributeType {
    raw: 3,
    code: AtRes,
    },
    length: 5,
    value: EapAkaAttributeValue::AtVecValue(0x80, vec ! [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,]),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::atmac(
    & [
    0x0b, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ],
    Ok((& [] as & [u8],
    (
    EapAkaAttribute {
    attribute_type: EapAkaAttributeType {
    raw: 0xb,
    code: AtMac,
    },
    length: 0x5,
    value: EapAkaAttributeValue::AtVecValue(0x00, vec ! [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ]),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::atautn(
    & [
    0x02, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ],
    Ok((& [] as & [u8],
    (
    EapAkaAttribute {
    attribute_type: EapAkaAttributeType {
    raw: 0x02,
    code: AtAutn,
    },
    length: 0x5,
    value: EapAkaAttributeValue::AtVecValue(0x00, vec ! [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]),
    },
    ErrorFlags::NONE,
    )))
    ),
    )]
    fn decode_it(input: &[u8], expected: IResult<&[u8], (EapAkaAttribute, ErrorFlags)>) {
        let res = EapAkaAttribute::parse(input);
        assert_eq!(res, expected);
        match res {
            Ok(attr) => {
                let mut buf : Vec<u8> = vec![];
                let attr = attr.1.0;
                let res = attr.write_to(&mut buf, BigEndian);
                assert_eq!(input, buf.as_slice());
            }
            Err(_) => {}
        }
    }

    #[test]
    fn decode_foo() {
        let input = &[
            0x03, 0x05, 0x00, 0x80, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        ];
        let result = EapAkaAttribute::parse(input);

        println!("Take a break {:?}", result)
    }

    #[test]
    fn test_h2() {
        let input = &[
            // Version: 1
            0x01, // Length: 20
            0x00, 0x00, 0x14, // Flags: 128 (Request)
            0x0f, // Code: 257 (Capability-Exchange)
            0x00, 0x01, 0x01, // Application ID: 0 (Diameter Common Messages)
            0x00, 0x00, 0x00, 0x00, // Hop-by-Hop ID: 0x53cafe6a
            0x53, 0xca, 0xfe, 0x6a, // End-to-End ID: 0x7dc0a11b
            0x7d, 0xc0, 0xa1, 0x1b,
        ];
        let expected = Ok((
            &[] as &[u8],
            (
                Header {
                    version: 1,
                    length: 20,
                    flags: 15,
                    code: 257,
                    app_id: 0,
                    hop_id: 0x53ca_fe6a,
                    end_id: 0x7dc0_a11b,
                },
                ErrorFlags::NON_ZERO_RESERVED,
            ),
        ));
        let h = Header::parse(input);
        assert_eq!(h, expected);
    }

    #[test]
    fn test_eap_r1() {
        let input = &[
            0x01, 0x00, 0x01, 0x2c, 0xc0, 0x00, 0x01, 0x0c, 0x01, 0x00, 0x00, 0x30, 0x31, 0x6b,
            0x38, 0xf9, 0x14, 0x00, 0x06, 0x68, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x43,
            0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x3b, 0x33, 0x39, 0x33, 0x3b, 0x32, 0x39,
            0x37, 0x36, 0x35, 0x39, 0x33, 0x37, 0x35, 0x36, 0x3b, 0x36, 0x63, 0x38, 0x32, 0x37,
            0x34, 0x38, 0x32, 0x2d, 0x37, 0x32, 0x65, 0x30, 0x2d, 0x34, 0x31, 0x66, 0x39, 0x2d,
            0x61, 0x33, 0x34, 0x61, 0x2d, 0x62, 0x39, 0x37, 0x35, 0x31, 0x36, 0x34, 0x32, 0x33,
            0x65, 0x38, 0x64, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x01, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x01, 0x1b, 0x40, 0x00, 0x00, 0x13, 0x74, 0x65, 0x6c, 0x65,
            0x6e, 0x6f, 0x72, 0x2e, 0x67, 0x72, 0x78, 0x00, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00,
            0x00, 0x0f, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x01, 0x28,
            0x40, 0x00, 0x00, 0x13, 0x74, 0x65, 0x6c, 0x65, 0x6e, 0x6f, 0x72, 0x2e, 0x67, 0x72,
            0x78, 0x00, 0x00, 0x00, 0x01, 0x12, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x3d, 0x30, 0x34, 0x31, 0x30, 0x30, 0x36,
            0x30, 0x35, 0x35, 0x34, 0x36, 0x31, 0x33, 0x32, 0x35, 0x33, 0x40, 0x6e, 0x61, 0x69,
            0x2e, 0x65, 0x70, 0x63, 0x2e, 0x6d, 0x6e, 0x63, 0x30, 0x36, 0x2e, 0x6d, 0x63, 0x63,
            0x34, 0x31, 0x30, 0x2e, 0x33, 0x67, 0x70, 0x70, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
            0x6b, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xce, 0x40, 0x00,
            0x00, 0x42, 0x02, 0x88, 0x00, 0x3a, 0x01, 0x30, 0x34, 0x31, 0x30, 0x30, 0x36, 0x30,
            0x35, 0x35, 0x34, 0x36, 0x31, 0x33, 0x32, 0x35, 0x33, 0x40, 0x6e, 0x61, 0x69, 0x2e,
            0x65, 0x70, 0x63, 0x2e, 0x6d, 0x6e, 0x63, 0x30, 0x36, 0x2e, 0x6d, 0x63, 0x63, 0x34,
            0x31, 0x30, 0x2e, 0x33, 0x67, 0x70, 0x70, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
            0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00,
        ];
        decode(input);
    }

    #[test]
    fn test_eap_r2() {
        let input = &[
            0x01, 0x00, 0x00, 0xbc, 0x40, 0x00, 0x01, 0x0c, 0x01, 0x00, 0x00, 0x30, 0x31, 0x6b,
            0x38, 0xf9, 0x14, 0x00, 0x06, 0x68, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x43,
            0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x3b, 0x33, 0x39, 0x33, 0x3b, 0x32, 0x39,
            0x37, 0x36, 0x35, 0x39, 0x33, 0x37, 0x35, 0x36, 0x3b, 0x36, 0x63, 0x38, 0x32, 0x37,
            0x34, 0x38, 0x32, 0x2d, 0x37, 0x32, 0x65, 0x30, 0x2d, 0x34, 0x31, 0x66, 0x39, 0x2d,
            0x61, 0x33, 0x34, 0x61, 0x2d, 0x62, 0x39, 0x37, 0x35, 0x31, 0x36, 0x34, 0x32, 0x33,
            0x65, 0x38, 0x64, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x01, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x01, 0x0c, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x03, 0xe9,
            0x00, 0x00, 0x01, 0xce, 0x00, 0x00, 0x00, 0x4c, 0x01, 0x88, 0x00, 0x44, 0x17, 0x01,
            0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
            0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x2e, 0x2e, 0x02, 0x05, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x0b, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        decode(input);
    }

    #[test]
    fn test_eap_r3() {
        let input = &[
            0x01, 0x00, 0x01, 0x20, 0xc0, 0x00, 0x01, 0x0c, 0x01, 0x00, 0x00, 0x30, 0x31, 0x6b,
            0x38, 0xfa, 0x14, 0x00, 0x06, 0x6a, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x43,
            0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x3b, 0x33, 0x39, 0x33, 0x3b, 0x32, 0x39,
            0x37, 0x36, 0x35, 0x39, 0x33, 0x37, 0x35, 0x36, 0x3b, 0x36, 0x63, 0x38, 0x32, 0x37,
            0x34, 0x38, 0x32, 0x2d, 0x37, 0x32, 0x65, 0x30, 0x2d, 0x34, 0x31, 0x66, 0x39, 0x2d,
            0x61, 0x33, 0x34, 0x61, 0x2d, 0x62, 0x39, 0x37, 0x35, 0x31, 0x36, 0x34, 0x32, 0x33,
            0x65, 0x38, 0x64, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x01, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x01, 0x1b, 0x40, 0x00, 0x00, 0x13, 0x74, 0x65, 0x6c, 0x65,
            0x6e, 0x6f, 0x72, 0x2e, 0x67, 0x72, 0x78, 0x00, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00,
            0x00, 0x0f, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x01, 0x28,
            0x40, 0x00, 0x00, 0x13, 0x74, 0x65, 0x6c, 0x65, 0x6e, 0x6f, 0x72, 0x2e, 0x67, 0x72,
            0x78, 0x00, 0x00, 0x00, 0x01, 0x12, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x3d, 0x30, 0x34, 0x31, 0x30, 0x30, 0x36,
            0x30, 0x35, 0x35, 0x34, 0x36, 0x31, 0x33, 0x32, 0x35, 0x33, 0x40, 0x6e, 0x61, 0x69,
            0x2e, 0x65, 0x70, 0x63, 0x2e, 0x6d, 0x6e, 0x63, 0x30, 0x36, 0x2e, 0x6d, 0x63, 0x63,
            0x34, 0x31, 0x30, 0x2e, 0x33, 0x67, 0x70, 0x70, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
            0x6b, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xce, 0x40, 0x00,
            0x00, 0x38, 0x02, 0x29, 0x00, 0x30, 0x17, 0x01, 0x00, 0x00, 0x03, 0x05, 0x00, 0x80,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x0b, 0x05, 0x00, 0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        ];
        decode(input);
    }

    #[test]
    fn build_it() {
        let attr = EapAkaAttribute::new(
            AtAutn,
            EapAkaAttributeValue::AtVecValue(16, b"0123456789abcdef".to_vec()),
        );
        println!("{:?}", attr);

        let attr = EapAkaAttribute::new(
            AtRes,
            EapAkaAttributeValue::AtVecValue(
                36,
                vec![
                    0b_1010_1010,
                    0b_1010_1010,
                    0b_1010_1010,
                    0b_1010_1010,
                    0b_1010_0000,
                ],
            ),
        );
        println!("{:?}", attr);
    }

    fn decode(input: &[u8]) {
        let diameter = Diameter {};
        let msg = diameter.parse(input, Direction::Unknown);
        // println!("{:?}", msg);
        match msg {
            Ok(result) => {
                println!("Unprocessed bytes: {}", result.0.len());
                match result.1 {
                    None => {}
                    Some(message) => {
                        println!("{:?}", message.header);
                        message.avps.iter().for_each(|avp| {
                            println!("{:?}", avp);
                            match avp.attribute.code {
                                AttributeCode::EapPayLoad => {
                                    let v = &avp.value;
                                    match v {
                                        Value::Unhandled(_) => {}
                                        Value::OctetString(_) => {}
                                        Value::Integer32(_) => {}
                                        Value::Integer64(_) => {}
                                        Value::Unsigned32(_) => {}
                                        Value::Unsigned64(_) => {}
                                        Value::Float32(_) => {}
                                        Value::Float64(_) => {}
                                        Value::Grouped(_) => {}
                                        Value::Enumerated(_) => {}
                                        Value::UTF8String(_) => {}
                                        Value::DiameterIdentity(_) => {}
                                        Value::DiameterURI(_) => {}
                                        Value::Address(_) => {}
                                        Value::Time(_) => {}
                                        Value::Eap(eap_payload) => {
                                            match &eap_payload.type_data {
                                                TypeData::Identity(_) => {}
                                                TypeData::EapAka(eap_aka) => {
                                                    match eap_aka.sub_type.code {
                                                        EapAkaSubTypeCode::AkaChallenge => {
                                                            eap_aka.attrs.iter().for_each(|attr| {
                                                                match attr.attribute_type.code {
                                                                    AtRand => {}
                                                                    AtAutn => {}
                                                                    AtRes => {
                                                                        let (len, val) = attr.value.len_val_vec().unwrap();
                                                                        println!("len: {}, val: {:?}", len, val)
                                                                    }
                                                                    AtAuts => {}
                                                                    AtPadding => {}
                                                                    AtNonceMt => {}
                                                                    AtPermanentIdReq => {}
                                                                    AtMac => {}
                                                                    AtNotification => {}
                                                                    AtAnyIdReq => {}
                                                                    AtIdentity => {}
                                                                    AtVersionList => {}
                                                                    AtSelectedVersion => {}
                                                                    AtFullAuthIdReq => {}
                                                                    AtCounter => {}
                                                                    AtCounterTooSmall => {}
                                                                    AtNonceS => {}
                                                                    AtClientErrorCode => {}
                                                                    AtIv => {}
                                                                    AtEncData => {}
                                                                    AtNextPseudonym => {}
                                                                    AtNextReauthId => {}
                                                                    AtCheckCode => {}
                                                                    AtResultInd => {}
                                                                    UnKnown => {}
                                                                }
                                                            })
                                                        }
                                                        EapAkaSubTypeCode::AkaAuthenticationReject => {}
                                                        EapAkaSubTypeCode::AkaIdentity => {}
                                                        EapAkaSubTypeCode::SimStart => {}
                                                        EapAkaSubTypeCode::SimChallenge => {}
                                                        EapAkaSubTypeCode::AkaNotificationAndSimNotification => {}
                                                        EapAkaSubTypeCode::AkaReauthenticationAndSimReauthentication => {}
                                                        EapAkaSubTypeCode::AkeClientErrorAndSimClientError => {}
                                                        EapAkaSubTypeCode::UnKnown => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        });
                    }
                }
            }
            Err(_) => {
                println!("Failed to parse message!");
            }
        }
    }

    #[rstest(
    input,
    expected,
    case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::new(4)))),
    case::diagnostic(
    & [
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 40 (Mandatory)
    0x40,
    // Length: 31
    0x00, 0x00, 0x1f,
    // Data: "backend.eap.testbed.aaa"
    0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
    0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
    // Padding: 1
    0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 264,
    code: AttributeCode::OriginHost,
    },
    flags: 0x40,
    length: 31,
    vendor_id: None,
    value: Value::DiameterIdentity("backend.eap.testbed.aaa".into()),
    padding: vec ! [0x00],
    },
    ErrorFlags::NONE,
    )))
    ),
    case::diagnostic_vendor_id(
    & [
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 0x80 (Vendor-Id)
    0x80,
    // Length: 12
    0x00, 0x00, 0x0c,
    // Vendor-Id: 1234567890
    0x49, 0x96, 0x02, 0xd2,
    // Data:
    // Padding:
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 264,
    code: AttributeCode::OriginHost,
    },
    flags: 0x80,
    length: 12,
    vendor_id: Some(1_234_567_890u32),
    value: Value::DiameterIdentity("".into()),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::unsigned_32_format(
    & [
    // Code: 266 (Vendor-Id)
    0x00, 0x00, 0x01, 0x0a,
    // Flags: 0x00
    0x00,
    // Length: 13,
    0x00, 0x00, 0x0d,
    // Vendor-Id:
    // Data:
    0x00, 0x00, 0x00, 0x7b,
    0x01,
    // Padding
    0x00, 0x00, 0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 266,
    code: AttributeCode::VendorId,
    },
    flags: 0x00,
    length: 13,
    vendor_id: None,
    value: Value::Unsigned32(123),
    padding: vec ! [0x00, 0x00, 0x00],
    },
    ErrorFlags::DATA_LENGTH,
    )))
    ),
    case::unsigned_64_format(
    & [
    // Code: 287 (Accounting-Realtime-Required)
    0x00, 0x00, 0x01, 0x1f,
    // Flags: 0x00
    0x00,
    // Length: 16,
    0x00, 0x00, 0x10,
    // Vendor-Id:
    // Data:
    0x00, 0x00, 0x00, 0x7B,
    0x01, 0x02, 0x02, 0x03,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 287,
    code: AttributeCode::AccountingSubSessionId,
    },
    flags: 0x00,
    length: 16,
    vendor_id: None,
    value: Value::Unsigned64(528_297_886_211),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::enumerated_format(
    & [
    // Code: 483 (Accounting-Realtime-Required)
    0x00, 0x00, 0x01, 0xe3,
    // Flags: 0x00
    0x00,
    // Length: 12,
    0x00, 0x00, 0x0c,
    // Vendor-Id:
    // Data: Grant-And-Store (2)
    0x00, 0x00, 0x00, 0x02,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 483,
    code: AttributeCode::AccountingRealtimeRequired,
    },
    flags: 0x00,
    length: 12,
    vendor_id: None,
    value: Value::Enumerated(2),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::octet_string_format(
    & [
    // Code: 44 (AcctSessionId)
    0x00, 0x00, 0x00, 0x2c,
    // Flags: 0x00
    0x00,
    // Length: 15,
    0x00, 0x00, 0x0f,
    // Vendor-Id:
    // Data:
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07,
    // Padding:
    0xef,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 44,
    code: AttributeCode::AcctSessionId,
    },
    flags: 0x00,
    length: 15,
    vendor_id: None,
    value: Value::OctetString(vec ! [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    padding: vec ! [0xef],
    },
    ErrorFlags::NON_ZERO_PADDING,
    )))
    ),
    case::utf8_string_format(
    & [
    // Code: 1 (Username)
    0x00, 0x00, 0x00, 0x01,
    // Flags: 0x00
    0x00,
    // Length: 20,
    0x00, 0x00, 0x14,
    // Vendor-Id:
    // Data: Hello World!
    0x48, 0x65, 0x6c, 0x6c,
    0x6f, 0x20, 0x57, 0x6f,
    0x72, 0x6c, 0x64, 0x21,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 1,
    code: AttributeCode::UserName,
    },
    flags: 0x00,
    length: 20,
    vendor_id: None,
    value: Value::UTF8String("Hello World!".into()),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::diameter_uri_format(
    & [
    // Code: 292 (RedirectHost)
    0x00, 0x00, 0x01, 0x24,
    // Flags: 0x00
    0x00,
    // Length: 19,
    0x00, 0x00, 0x13,
    // Vendor-Id:
    // Data: example.com
    0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d,
    // Padding:
    0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 292,
    code: AttributeCode::RedirectHost,
    },
    flags: 0x00,
    length: 19,
    vendor_id: None,
    value: Value::DiameterURI("example.com".into()),
    padding: vec ! [0x00],
    },
    ErrorFlags::NONE,
    )))
    ),
    case::address_v4_format(
    & [
    // Code: 257 (HostIPAddress)
    0x00, 0x00, 0x01, 0x01,
    // Flags: 0x0f
    0x0f,
    // Length: 12,
    0x00, 0x00, 0x0c,
    // Vendor-Id:
    // Data: 10.10.0.1
    0x0a, 0x0a, 0x00, 0x01,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 257,
    code: AttributeCode::HostIPAddress,
    },
    flags: 0x0f,
    length: 12,
    vendor_id: None,
    value: Value::Address(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1))),
    padding: Vec::new(),
    },
    ErrorFlags::NON_ZERO_RESERVED,
    )))
    ),
    case::address_v6_format(
    & [
    // Code: 257 (HostIPAddress)
    0x00, 0x00, 0x01, 0x01,
    // Flags: 0x00
    0x00,
    // Length: 24,
    0x00, 0x00, 0x18,
    // Vendor-Id:
    // Data: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    0x20, 0x01, 0x0d, 0xb8,
    0x85, 0xa3, 0x00, 0x00,
    0x00, 0x00, 0x8a, 0x2e,
    0x03, 0x70, 0x73, 0x34,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 257,
    code: AttributeCode::HostIPAddress,
    },
    flags: 0x00,
    length: 24,
    vendor_id: None,
    value: Value::Address(IpAddr::V6(Ipv6Addr::new(
    0x2001, 0x0db8, 0x85a3, 0x0000,
    0x0000, 0x8a2e, 0x0370, 0x7334))),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::time_format(
    & [
    // Code: 55 (EventTimestamp)
    0x00, 0x00, 0x00, 0x37,
    // Flags: 0x00
    0x00,
    // Length: 12,
    0x00, 0x00, 0x0c,
    // Vendor-Id:
    // Data: 3794601600 (March 31, 2021)
    0xe2, 0x2d, 0x06, 0x80
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 55,
    code: AttributeCode::EventTimestamp,
    },
    flags: 0x00,
    length: 12,
    vendor_id: None,
    value: Value::Time(3_794_601_600),
    padding: Vec::new(),
    },
    ErrorFlags::NONE,
    )))
    ),
    case::grouped_format(
    & [
    // Code: 297 (ExperimentalResult)
    0x00, 0x00, 0x01, 0x29,
    // Flags: 0x00
    0x00,
    // Length: 44,
    0x00, 0x00, 0x2c,
    // Vendor-Id:
    // Data:

    // AVPs[0]
    // Code: 264 (OriginHost)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 0x00
    0x00,
    // Length: 19,
    0x00, 0x00, 0x13,
    // Vendor-Id:
    // Data: example.com
    0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d,
    // Padding:
    0x01,

    // AVPs[1]
    // Code: 44 ( AcctSessionId)
    0x00, 0x00, 0x00, 0x2c,
    // Flags: 0x0f,
    0x0f,
    // Length: 15,
    0x00, 0x00, 0x0f,
    // Vendor-Id:
    // Data:
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07,
    // Padding:
    0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 297,
    code: AttributeCode::ExperimentalResult,
    },
    flags: 0x00,
    length: 44,
    vendor_id: None,
    value: Value::Grouped(vec ! [
    AVP {
    attribute: Attribute {
    raw: 264,
    code: AttributeCode::OriginHost,
    },
    flags: 0x00,
    length: 19,
    vendor_id: None,
    value: Value::DiameterIdentity("example.com".into()),
    padding: vec ! [0x01],
    },
    AVP {
    attribute: Attribute {
    raw: 44,
    code: AttributeCode::AcctSessionId,
    },
    flags: 0x0f,
    length: 15,
    vendor_id: None,
    value: Value::OctetString(vec ! [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    padding: vec ! [0x00],
    }]),
    padding: Vec::new(),
    },
    ErrorFlags::NON_ZERO_PADDING | ErrorFlags::NON_ZERO_RESERVED
    )))
    ),
    case::invalid_utf8(
    & [
    // Code: 1 (Username)
    0x00, 0x00, 0x00, 0x01,
    // Flags: 0x00
    0x00,
    // Length: 12,
    0x00, 0x00, 0x0c,
    // Vendor-Id:
    // Data:
    0xfe, 0xfe, 0xff, 0xff,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 1,
    code: AttributeCode::UserName,
    },
    flags: 0x00,
    length: 12,
    vendor_id: None,
    value: Value::Unhandled(vec ! [0xfe, 0xfe, 0xff, 0xff]),
    padding: Vec::new(),
    },
    ErrorFlags::DATA_VALUE,
    )))
    ),
    case::invalid_address(
    & [
    // Code: 257 (HostIPAddress)
    0x00, 0x00, 0x01, 0x01,
    // Flags: 0x00
    0x00,
    // Length: 13,
    0x00, 0x00, 0x0d,
    // Vendor-Id:
    // Data: 10.10.0.1.1 (Invalid)
    0x0a, 0x0a, 0x00, 0x01, 0x01,
    // Padding
    0x00, 0x00, 0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 257,
    code: AttributeCode::HostIPAddress,
    },
    flags: 0x00,
    length: 13,
    vendor_id: None,
    value: Value::Unhandled(vec ! [0x0a, 0x0a, 0x00, 0x01, 0x01]),
    padding: vec ! [0x00, 0x00, 0x00],
    },
    ErrorFlags::DATA_LENGTH,
    )))
    ),
    case::unhandled(
    & [
    // Code: 2
    0x00, 0x00, 0x00, 0x02,
    // Flags: 0x00
    0x00,
    // Length: 13,
    0x00, 0x00, 0x0d,
    // Vendor-Id:
    // Data: 10.10.0.1.1 (Invalid)
    0x0a, 0x0a, 0x00, 0x01, 0x01,
    // Padding
    0x00, 0x00, 0x00,
    ],
    Ok((& [] as & [u8],
    (
    AVP {
    attribute: Attribute {
    raw: 2,
    code: AttributeCode::Unknown,
    },
    flags: 0x00,
    length: 13,
    vendor_id: None,
    value: Value::Unhandled(vec ! [0x0a, 0x0a, 0x00, 0x01, 0x01]),
    padding: vec ! [0x00, 0x00, 0x00],
    },
    ErrorFlags::NONE,
    )))
    )
    )]
    fn test_avp(input: &[u8], expected: IResult<&[u8], (AVP, ErrorFlags)>) {
        assert_eq!(AVP::parse(input), expected);
    }

    #[rstest(
    input,
    expected,
    case::empty(b"", Err(Error::incomplete_needed(1))),
    case::header(
    & [
    // Version: 1
    0x01,
    // Length: 20
    0x00, 0x00, 0x14,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Ok((& [] as & [u8],
    Some(Message {
    header: Header {
    version: 1,
    length: 20,
    flags: 128,
    code: 257,
    app_id: 0,
    hop_id: 0x53ca_fe6a,
    end_id: 0x7dc0_a11b,
    },
    avps: Vec::new(),
    error_flags: ErrorFlags::NONE,
    })
    ))
    ),
    case::full_message(
    & [
    // Header
    // Version: 1
    0x01,
    // Length: 64
    0x00, 0x00, 0x40,
    // Flags: 128 (Request)
    0x8f,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,

    //AVPs[0]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 40 (Mandatory)
    0x40,
    // Length: 31
    0x00, 0x00, 0x1f,
    // Data: "backend.eap.testbed.aaa"
    0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
    0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
    // Padding: 1
    0x01,

    // AVPS[1]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 0x80 (Vendor-Id)
    0x80,
    // Length: 12
    0x00, 0x00, 0x0c,
    // Vendor-Id: 1234567890
    0x49, 0x96, 0x02, 0xd2,
    // Data:
    // Padding:
    ],
    Ok((& [] as & [u8],
    Some(Message {
    header: Header {
    version: 1,
    length: 64,
    flags: 143,
    code: 257,
    app_id: 0,
    hop_id: 0x53ca_fe6a,
    end_id: 0x7dc0_a11b,
    },
    avps: vec ! [
    AVP {
    attribute: Attribute {
    raw: 264,
    code: AttributeCode::OriginHost,
    },
    flags: 0x40,
    length: 31,
    vendor_id: None,
    value: Value::DiameterIdentity("backend.eap.testbed.aaa".into()),
    padding: vec ! [0x01],
    },
    AVP {
    attribute: Attribute {
    raw: 264,
    code: AttributeCode::OriginHost,
    },
    flags: 0x80,
    length: 12,
    vendor_id: Some(1_234_567_890u32),
    value: Value::DiameterIdentity("".into()),
    padding: Vec::new(),
    },
    ],
    error_flags: ErrorFlags::NON_ZERO_RESERVED | ErrorFlags::NON_ZERO_PADDING,
    })
    ))),
    case::incomplete(
    & [
    // Header
    // Version: 1
    0x01,
    // Length: 66
    0x00, 0x00, 0x42,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,

    //AVPs[0]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 40 (Mandatory)
    0x40,
    // Length: 31
    0x00, 0x00, 0x1f,
    // Data: "backend.eap.testbed.aaa"
    0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
    0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
    // Padding: 1
    0x00,

    // AVPS[1]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 0x80 (Vendor-Id)
    0x80,
    // Length: 14
    0x00, 0x00, 0x0e,
    // Vendor-Id: 1234567890
    0x49, 0x96, 0x02, 0xd2,
    // Data:
    // Padding:
    ],
    Err(Error::incomplete_needed(2))
    ),
    case::invalid_avp(
    & [
    // Header
    // Version: 1
    0x01,
    // Length: 64
    0x00, 0x00, 0x40,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,

    //AVPs[0]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 40 (Mandatory)
    0x40,
    // Length: 31
    0x00, 0x00, 0x1f,
    // Data: "backend.eap.testbed.aaa"
    0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
    0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
    // Padding: 1
    0x00,

    // AVPS[1]
    // Code: 264 (Origin-Host)
    0x00, 0x00, 0x01, 0x08,
    // Flags: 0x80 (Vendor-Id)
    0x80,
    // Length: 14
    0x00, 0x00, 0x0e,
    // Vendor-Id: 1234567890
    0x49, 0x96, 0x02, 0xd2,
    // Data:
    // Padding:
    ],
    Err(Error::parse(Some("Many0".to_string()))),
    ),
    )]
    fn test_parse(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let diameter = Diameter {};

        assert_eq!(diameter.parse(input, Direction::Unknown), expected);
    }

    #[rstest(
    input,
    expected,
    case::empty(b"", Status::Incomplete),
    case::hello_world(b"hello world", Status::Unrecognized),
    case::header(
    & [
    // Version: 1
    0x01,
    // Length: 20
    0x00, 0x00, 0x14,
    // Flags: 128 (Request)
    0x80,
    // Code: 257 (Capability-Exchange)
    0x00, 0x01, 0x01,
    // Application ID: 0 (Diameter Common Messages)
    0x00, 0x00, 0x00, 0x00,
    // Hop-by-Hop ID: 0x53cafe6a
    0x53, 0xca, 0xfe, 0x6a,
    // End-to-End ID: 0x7dc0a11b
    0x7d, 0xc0, 0xa1, 0x1b,
    ],
    Status::Recognized
    ),
    )]
    fn test_probe(input: &[u8], expected: Status) {
        let diameter = Diameter {};

        assert_eq!(diameter.probe(input, Direction::Unknown), expected);
    }
}
