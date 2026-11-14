// Definisi protobuf manual (prost derive) -> tidak perlu protoc.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HandshakeMessage {
    #[prost(message, optional, tag = "2")]
    pub client_hello: Option<ClientHello>,
    #[prost(message, optional, tag = "3")]
    pub server_hello: Option<ServerHello>,
    #[prost(message, optional, tag = "4")]
    pub client_finish: Option<ClientFinish>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientHello {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ephemeral: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub static_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub payload: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerHello {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ephemeral: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub static_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub payload: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientFinish {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub static_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub payload: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppVersion {
    #[prost(uint32, optional, tag = "1")]
    pub primary: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub secondary: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub tertiary: Option<u32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserAgent {
    #[prost(int32, optional, tag = "1")]
    pub platform: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub app_version: Option<AppVersion>,
    #[prost(string, optional, tag = "3")]
    pub mcc: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub mnc: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub os_version: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub manufacturer: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub device: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub os_build_number: Option<String>,
    #[prost(int32, optional, tag = "10")]
    pub release_channel: Option<i32>,
    #[prost(string, optional, tag = "11")]
    pub locale_language: Option<String>,
    #[prost(string, optional, tag = "12")]
    pub locale_country: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WebInfo {
    #[prost(int32, optional, tag = "4")]
    pub web_sub_platform: Option<i32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DevicePairingData {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub e_regid: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub e_keytype: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub e_ident: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub e_skey_id: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub e_skey_val: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub e_skey_sig: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub build_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub device_props: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientPayload {
    #[prost(bool, optional, tag = "3")]
    pub passive: Option<bool>,
    #[prost(message, optional, tag = "5")]
    pub user_agent: Option<UserAgent>,
    #[prost(message, optional, tag = "6")]
    pub web_info: Option<WebInfo>,
    #[prost(int32, optional, tag = "12")]
    pub connect_type: Option<i32>,
    #[prost(int32, optional, tag = "13")]
    pub connect_reason: Option<i32>,
    #[prost(message, optional, tag = "19")]
    pub device_pairing_data: Option<DevicePairingData>,
    #[prost(bool, optional, tag = "33")]
    pub pull: Option<bool>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceProps {
    #[prost(string, optional, tag = "1")]
    pub os: Option<String>,
    #[prost(message, optional, tag = "2")]
    pub version: Option<AppVersion>,
    #[prost(int32, optional, tag = "3")]
    pub platform_type: Option<i32>,
    #[prost(bool, optional, tag = "4")]
    pub require_full_sync: Option<bool>,
}
