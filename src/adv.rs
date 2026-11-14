#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AdvSignedDeviceIdentityHmac {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub details: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub hmac: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "3")]
    pub account_type: Option<i32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AdvSignedDeviceIdentity {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub details: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub account_signature_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub account_signature: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub device_signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AdvDeviceIdentity {
    #[prost(uint32, optional, tag = "1")]
    pub raw_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub timestamp: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub key_index: Option<u32>,
    #[prost(int32, optional, tag = "4")]
    pub account_type: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    pub device_type: Option<i32>,
}
