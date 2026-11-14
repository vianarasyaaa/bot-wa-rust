use crate::proto::{UserAgent, WebInfo};

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LoginPayload {
    #[prost(uint64, optional, tag = "1")]
    pub username: Option<u64>,
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
    #[prost(uint32, optional, tag = "18")]
    pub device: Option<u32>,
    #[prost(bool, optional, tag = "33")]
    pub pull: Option<bool>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtendedTextMessage {
    #[prost(string, optional, tag = "1")]
    pub text: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(string, optional, tag = "1")]
    pub conversation: Option<String>,
    #[prost(message, optional, tag = "6")]
    pub extended_text_message: Option<ExtendedTextMessage>,
}
