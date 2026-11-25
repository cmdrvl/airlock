use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub mod anthropic_messages;
pub mod gemini_generate_content;
pub mod generic_json;
pub mod openai_responses;

pub use anthropic_messages::{ANTHROPIC_MESSAGES_ADAPTER_NAME, AnthropicMessagesAdapter};
pub use gemini_generate_content::{
    GEMINI_GENERATE_CONTENT_ADAPTER_NAME, GeminiGenerateContentAdapter,
};
pub use generic_json::{GENERIC_JSON_ADAPTER_NAME, GenericJsonAdapter};
pub use openai_responses::{OPENAI_RESPONSES_ADAPTER_NAME, OpenAiResponsesAdapter};

pub const OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME: &str = "openai_chat_completions";

/// Every adapter name `select` accepts, in the order they are documented.
pub const ADAPTER_NAMES: [&str; 5] = [
    OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME,
    OPENAI_RESPONSES_ADAPTER_NAME,
    ANTHROPIC_MESSAGES_ADAPTER_NAME,
    GEMINI_GENERATE_CONTENT_ADAPTER_NAME,
    GENERIC_JSON_ADAPTER_NAME,
];

// `schemas/openai_chat_completions_request.schema.json` is generated from the
// OpenAI OpenAPI schema and identifies its source commit in `x-airlock-source`.
// Keep this allowlist aligned with CreateChatCompletionRequest's properties.
const OPENAI_CHAT_COMPLETIONS_TRANSPORT_KEYS: &[&str] = &[
    "audio",
    "frequency_penalty",
    "function_call",
    "functions",
    "logit_bias",
    "logprobs",
    "max_completion_tokens",
    "max_tokens",
    "messages",
    "metadata",
    "modalities",
    "model",
    "moderation",
    "n",
    "parallel_tool_calls",
    "prediction",
    "presence_penalty",
    "prompt_cache_key",
    "prompt_cache_options",
    "prompt_cache_retention",
    "reasoning_effort",
    "response_format",
    "safety_identifier",
    "seed",
    "service_tier",
    "stop",
    "store",
    "stream",
    "stream_options",
    "temperature",
    "tool_choice",
    "tools",
    "top_logprobs",
    "top_p",
    "user",
    "verbosity",
    "web_search_options",
];

const RESERVED_REQUEST_KEYS: [&str; 5] = [
    "messages",
    "model",
    "temperature",
    "max_tokens",
    "response_format",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub model_id: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub response_format: Option<Value>,
    pub additional_params: Option<Map<String, Value>>,
}

impl TransportConfig {
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            model_id: model_id.into(),
            temperature: None,
            max_tokens: None,
            response_format: None,
            additional_params: None,
        }
    }
}

/// One piece of a vendor request that a screener has to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenablePart {
    /// RFC 6901 JSON pointer to the value inside the request payload.
    pub pointer: String,
    pub kind: PartKind,
    /// The text, the base64 payload, or the URL / file id, depending on `kind`.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartKind {
    /// Model-visible text: prompts, tool-call arguments, tool results, tool definitions.
    Text,
    /// Inline base64 media (images, documents, audio, files). `data` is the base64 payload.
    Base64Media { media_type: String },
    /// A URL or provider file id the vendor would fetch. Its bytes are not in the request.
    RemoteReference,
}

pub trait Adapter {
    fn name(&self) -> &str;

    /// Top-level request keys declared by the vendor transport schema.
    fn transport_keys(&self) -> Vec<&str>;

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope>;

    /// Restore the canonical prompt messages from a vendor request envelope.
    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope>;

    /// The model identifier carried by a request, or `None` when the request has none.
    fn model_id(&self, request_payload: &Value) -> Option<String> {
        request_payload
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(str::to_string)
    }

    /// Every part of the request a screener must inspect, in document order.
    ///
    /// Anything the adapter does not recognise is walked generically, so each string leaf is
    /// returned as `Text` rather than skipped. Only declared structural fields (model id,
    /// block `type` tags, opaque signatures and ids) are left out.
    fn extract_screenable_parts(
        &self,
        request_payload: &Value,
    ) -> Result<Vec<ScreenablePart>, RefusalEnvelope>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiChatCompletionsAdapter;

impl Adapter for OpenAiChatCompletionsAdapter {
    fn name(&self) -> &str {
        OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME
    }

    fn transport_keys(&self) -> Vec<&str> {
        OPENAI_CHAT_COMPLETIONS_TRANSPORT_KEYS.to_vec()
    }

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope> {
        let model_id = config.model_id.trim();
        if model_id.is_empty() {
            return Err(RefusalEnvelope::bad_request(
                "transport config requires a non-empty model_id",
                json!({ "field": "model_id" }),
            ));
        }

        if let Some(temperature) = config.temperature {
            if !temperature.is_finite() {
                return Err(RefusalEnvelope::bad_request(
                    "transport config temperature must be finite",
                    json!({
                        "field": "temperature",
                        "value": temperature.to_string(),
                    }),
                ));
            }
        }

        let messages = prompt_payload
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_prompt(
                    "prompt payload must contain a messages array",
                    json!({ "field": "messages" }),
                )
            })?;

        let messages = messages
            .iter()
            .enumerate()
            .map(|(index, message)| encode_message(message, index))
            .collect::<Result<Vec<_>, _>>()?;

        let mut request = Map::new();
        request.insert("model".to_string(), Value::String(model_id.to_string()));
        request.insert("messages".to_string(), Value::Array(messages));

        if let Some(temperature) = config.temperature {
            request.insert("temperature".to_string(), json!(temperature));
        }
        if let Some(max_tokens) = config.max_tokens {
            request.insert("max_tokens".to_string(), json!(max_tokens));
        }
        if let Some(response_format) = &config.response_format {
            request.insert("response_format".to_string(), response_format.clone());
        }

        if let Some(additional_params) = &config.additional_params {
            for (key, value) in additional_params {
                if RESERVED_REQUEST_KEYS.contains(&key.as_str()) {
                    return Err(RefusalEnvelope::bad_request(
                        "additional_params may not override reserved request fields",
                        json!({ "field": key }),
                    ));
                }
                request.insert(key.clone(), value.clone());
            }
        }

        Ok(sort_value(Value::Object(request)))
    }

    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope> {
        let messages = request_payload
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "OpenAI Chat Completions request must contain a messages array",
                    json!({ "field": "messages" }),
                )
            })?;

        let messages = messages
            .iter()
            .map(|message| {
                let mut message = message.as_object().cloned().ok_or_else(|| {
                    RefusalEnvelope::bad_request(
                        "OpenAI Chat Completions messages must be objects",
                        json!({ "field": "messages" }),
                    )
                })?;

                if message.get("role").and_then(Value::as_str) == Some("user") {
                    if let Some(content) = message.get_mut("content") {
                        *content = decode_user_content(content);
                    }
                }

                Ok(Value::Object(message))
            })
            .collect::<Result<Vec<_>, RefusalEnvelope>>()?;

        Ok(sort_value(json!({ "messages": messages })))
    }

    fn extract_screenable_parts(
        &self,
        request_payload: &Value,
    ) -> Result<Vec<ScreenablePart>, RefusalEnvelope> {
        walk_request(request_payload, &chat_media_parts)
    }
}

/// Classify Chat Completions media content parts: `image_url`, `input_audio` and `file`.
pub(crate) fn chat_media_parts(
    object: &Map<String, Value>,
    pointer: &str,
    out: &mut Vec<ScreenablePart>,
) -> bool {
    match object.get("type").and_then(Value::as_str) {
        Some("image_url") => {
            if let Some(url) = object
                .get("image_url")
                .and_then(|image| image.get("url"))
                .and_then(Value::as_str)
            {
                let pointer = pointer_child(&pointer_child(pointer, "image_url"), "url");
                out.push(classify_reference(pointer, url));
                return true;
            }
            false
        }
        Some("input_audio") => {
            let audio = object.get("input_audio").and_then(Value::as_object);
            if let Some((data, format)) = audio.and_then(|audio| {
                Some((
                    audio.get("data").and_then(Value::as_str)?,
                    audio.get("format").and_then(Value::as_str)?,
                ))
            }) {
                out.push(ScreenablePart {
                    pointer: pointer_child(&pointer_child(pointer, "input_audio"), "data"),
                    kind: PartKind::Base64Media {
                        media_type: format!("audio/{format}"),
                    },
                    data: data.to_string(),
                });
                return true;
            }
            false
        }
        Some("file") => {
            let Some(file) = object.get("file").and_then(Value::as_object) else {
                return false;
            };
            let file_pointer = pointer_child(pointer, "file");
            let mut recognised = false;
            if let Some(data) = file.get("file_data").and_then(Value::as_str) {
                out.push(classify_inline_file(
                    pointer_child(&file_pointer, "file_data"),
                    data,
                ));
                recognised = true;
            }
            if let Some(file_id) = file.get("file_id").and_then(Value::as_str) {
                out.push(ScreenablePart {
                    pointer: pointer_child(&file_pointer, "file_id"),
                    kind: PartKind::RemoteReference,
                    data: file_id.to_string(),
                });
                recognised = true;
            }
            recognised
        }
        _ => false,
    }
}

fn encode_message(message: &Value, index: usize) -> Result<Value, RefusalEnvelope> {
    let mut message = message.as_object().cloned().ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must be objects",
            json!({ "field": "messages", "index": index }),
        )
    })?;

    let role = message.get("role").and_then(Value::as_str).ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include a string role",
            json!({ "field": format!("messages[{index}].role") }),
        )
    })?;

    let content = message.get("content").ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include content",
            json!({ "field": format!("messages[{index}].content") }),
        )
    })?;

    if !content.is_string() {
        let encoded = canonical_json(content);
        let wire_content = if role == "user" {
            // Chat Completions accepts text content parts for user messages.
            // A single text part keeps the structured payload deterministic and
            // gives unwrap() an unambiguous transport marker to reverse.
            json!([{ "type": "text", "text": encoded }])
        } else {
            // Non-user message roles accept string content. Keep their values
            // JSON-encoded without adding a user-only content part.
            Value::String(encoded)
        };
        message.insert("content".to_string(), wire_content);
    }

    Ok(sort_value(Value::Object(message)))
}

fn decode_user_content(content: &Value) -> Value {
    let Some(parts) = content.as_array() else {
        return content.clone();
    };
    let [part] = parts.as_slice() else {
        return content.clone();
    };
    let Some(part) = part.as_object() else {
        return content.clone();
    };
    if part.len() != 2 || part.get("type").and_then(Value::as_str) != Some("text") {
        return content.clone();
    }
    let Some(encoded) = part.get("text").and_then(Value::as_str) else {
        return content.clone();
    };

    let Ok(decoded) = serde_json::from_str::<Value>(encoded) else {
        return content.clone();
    };
    if canonical_json(&decoded) == encoded {
        decoded
    } else {
        content.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Adapter selection
// ---------------------------------------------------------------------------------------------

/// An explicit transport declaration: which adapter to use and, for `generic_json`, where the
/// system prompt and messages live in the vendor request. Supplied as a JSON file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportDeclaration {
    pub adapter: Option<String>,
    /// `generic_json` only: JSON pointer to the messages array.
    pub messages_pointer: Option<String>,
    /// `generic_json` only: JSON pointer to the system prompt string.
    pub system_pointer: Option<String>,
    /// `generic_json` only: JSON pointer to the model id. Defaults to `/model`.
    pub model_pointer: Option<String>,
    /// `generic_json` only: the top-level request keys the vendor declares.
    pub transport_keys: Option<Vec<String>>,
}

impl TransportDeclaration {
    fn has_generic_fields(&self) -> bool {
        self.messages_pointer.is_some()
            || self.system_pointer.is_some()
            || self.model_pointer.is_some()
            || self.transport_keys.is_some()
    }
}

/// Choose the adapter for a request. An adapter named in the declaration always wins;
/// otherwise the request shape decides, deterministically:
///
/// - `contents` array: Gemini `generateContent`
/// - `input` (no `messages`/`contents`): OpenAI Responses
/// - `messages` array: Anthropic Messages when the request carries a top-level key only that
///   API declares (for example `system`), OpenAI Chat Completions otherwise
///
/// A request that fits none of these, or fits two, is refused rather than guessed at.
pub fn select(
    request_payload: &Value,
    declared: Option<&TransportDeclaration>,
) -> Result<Box<dyn Adapter>, RefusalEnvelope> {
    let Some(declaration) = declared else {
        return detect(request_payload);
    };
    match declaration.adapter.as_deref() {
        Some(GENERIC_JSON_ADAPTER_NAME) => {
            Ok(Box::new(GenericJsonAdapter::from_declaration(declaration)?))
        }
        Some(name) => {
            if declaration.has_generic_fields() {
                return Err(RefusalEnvelope::bad_input(
                    "transport pointers and transport_keys apply only to the generic_json adapter",
                    json!({ "adapter": name }),
                ));
            }
            vendor_adapter(name)
        }
        None if declaration.has_generic_fields() => Err(RefusalEnvelope::bad_input(
            "transport declares generic_json fields but no adapter",
            json!({ "expected": { "adapter": GENERIC_JSON_ADAPTER_NAME } }),
        )),
        None => detect(request_payload),
    }
}

fn vendor_adapter(name: &str) -> Result<Box<dyn Adapter>, RefusalEnvelope> {
    match name {
        OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME => Ok(Box::new(OpenAiChatCompletionsAdapter)),
        OPENAI_RESPONSES_ADAPTER_NAME => Ok(Box::new(OpenAiResponsesAdapter)),
        ANTHROPIC_MESSAGES_ADAPTER_NAME => Ok(Box::new(AnthropicMessagesAdapter)),
        GEMINI_GENERATE_CONTENT_ADAPTER_NAME => Ok(Box::new(GeminiGenerateContentAdapter)),
        _ => Err(RefusalEnvelope::bad_input(
            "unknown adapter in transport declaration",
            json!({ "adapter": name, "supported": ADAPTER_NAMES }),
        )),
    }
}

fn detect(request_payload: &Value) -> Result<Box<dyn Adapter>, RefusalEnvelope> {
    let object = request_payload.as_object().ok_or_else(|| {
        RefusalEnvelope::bad_request(
            "request payload must be a JSON object",
            json!({ "field": "" }),
        )
    })?;

    let shapes = [
        (
            "contents",
            object.get("contents").is_some_and(Value::is_array),
        ),
        ("input", object.contains_key("input")),
        (
            "messages",
            object.get("messages").is_some_and(Value::is_array),
        ),
    ];
    let present: Vec<&str> = shapes
        .iter()
        .filter(|(_, present)| *present)
        .map(|(name, _)| *name)
        .collect();

    match present.as_slice() {
        ["contents"] => Ok(Box::new(GeminiGenerateContentAdapter)),
        ["input"] => Ok(Box::new(OpenAiResponsesAdapter)),
        ["messages"] => detect_messages_vendor(object),
        [] => Err(RefusalEnvelope::bad_request(
            "request does not match a known vendor shape",
            json!({
                "expected_one_of": ["messages (array)", "contents (array)", "input"],
                "hint": "declare the adapter with a transport file",
            }),
        )),
        _ => Err(RefusalEnvelope::bad_request(
            "request mixes vendor shapes",
            json!({
                "found": present,
                "hint": "declare the adapter with a transport file",
            }),
        )),
    }
}

fn detect_messages_vendor(
    object: &Map<String, Value>,
) -> Result<Box<dyn Adapter>, RefusalEnvelope> {
    let chat_adapter = OpenAiChatCompletionsAdapter;
    let anthropic_adapter = AnthropicMessagesAdapter;
    let chat_keys = chat_adapter.transport_keys();
    let anthropic_keys = anthropic_adapter.transport_keys();

    let chat_only: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| chat_keys.contains(key) && !anthropic_keys.contains(key))
        .collect();
    let anthropic_only: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| anthropic_keys.contains(key) && !chat_keys.contains(key))
        .collect();

    match (chat_only.is_empty(), anthropic_only.is_empty()) {
        (false, false) => Err(RefusalEnvelope::bad_request(
            "request mixes OpenAI Chat Completions and Anthropic Messages fields",
            json!({
                OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME: chat_only,
                ANTHROPIC_MESSAGES_ADAPTER_NAME: anthropic_only,
                "hint": "declare the adapter with a transport file",
            }),
        )),
        (true, false) => Ok(Box::new(AnthropicMessagesAdapter)),
        // Only shared keys, or only Chat Completions keys: Chat Completions, the default.
        _ => Ok(Box::new(OpenAiChatCompletionsAdapter)),
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers shared by the vendor adapters
// ---------------------------------------------------------------------------------------------

/// Append one RFC 6901 reference token to a JSON pointer.
pub(crate) fn pointer_child(base: &str, segment: &str) -> String {
    format!("{base}/{}", segment.replace('~', "~0").replace('/', "~1"))
}

pub(crate) fn pointer_index(base: &str, index: usize) -> String {
    format!("{base}/{index}")
}

/// Classify a URL-or-data-URI string as inline base64 media or a remote reference.
pub(crate) fn classify_reference(pointer: String, url: &str) -> ScreenablePart {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            if let Some(media_type) = meta.strip_suffix(";base64") {
                return ScreenablePart {
                    pointer,
                    kind: PartKind::Base64Media {
                        media_type: media_type.to_string(),
                    },
                    data: payload.to_string(),
                };
            }
        }
    }
    ScreenablePart {
        pointer,
        kind: PartKind::RemoteReference,
        data: url.to_string(),
    }
}

/// Classify a `file_data` string: a data URI, or bare base64 whose media type is not stated.
pub(crate) fn classify_inline_file(pointer: String, data: &str) -> ScreenablePart {
    if data.starts_with("data:") {
        return classify_reference(pointer, data);
    }
    ScreenablePart {
        pointer,
        kind: PartKind::Base64Media {
            media_type: "application/octet-stream".to_string(),
        },
        data: data.to_string(),
    }
}

/// Recognises a vendor media object and appends a part for each payload string it carries
/// (a base64 blob, a data URI, a remote reference), using that string's own pointer. Returns
/// `true` when it recognised the object. The walker still reports every other string in a
/// recognised object as text, so a classifier never has to account for the rest of the object.
pub(crate) type MediaClassifier =
    dyn Fn(&Map<String, Value>, &str, &mut Vec<ScreenablePart>) -> bool;

/// Walk a whole request and return every string in it as exactly one screenable part. The
/// payload strings the vendor `classify` function recognises are reported as base64 media or
/// remote references; every other string is text.
///
/// Nothing is skipped by key name. Requests carry free-form JSON in places (tool inputs,
/// metadata, function arguments), so a key such as `type` or `role` can hold arbitrary text
/// there, and a screener must not be told to look away from it.
pub(crate) fn walk_request(
    request_payload: &Value,
    classify: &MediaClassifier,
) -> Result<Vec<ScreenablePart>, RefusalEnvelope> {
    let root = request_payload.as_object().ok_or_else(|| {
        RefusalEnvelope::bad_request(
            "request payload must be a JSON object",
            json!({ "field": "" }),
        )
    })?;

    let mut parts = Vec::new();
    let no_claims = HashSet::new();
    for (key, value) in root {
        walk_value(
            value,
            &pointer_child("", key),
            classify,
            &no_claims,
            &mut parts,
        );
    }
    Ok(parts)
}

/// `claimed` holds pointers a classifier already reported; the walker does not report them
/// again.
fn walk_value(
    value: &Value,
    pointer: &str,
    classify: &MediaClassifier,
    claimed: &HashSet<String>,
    out: &mut Vec<ScreenablePart>,
) {
    match value {
        Value::String(text) => {
            if !claimed.contains(pointer) {
                out.push(ScreenablePart {
                    pointer: pointer.to_string(),
                    kind: PartKind::Text,
                    data: text.clone(),
                });
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_value(item, &pointer_index(pointer, index), classify, claimed, out);
            }
        }
        Value::Object(object) => {
            let before = out.len();
            if classify(object, pointer, out) {
                let mut now_claimed = claimed.clone();
                now_claimed.extend(out[before..].iter().map(|part| part.pointer.clone()));
                for (key, child) in object {
                    walk_value(
                        child,
                        &pointer_child(pointer, key),
                        classify,
                        &now_claimed,
                        out,
                    );
                }
            } else {
                for (key, child) in object {
                    walk_value(child, &pointer_child(pointer, key), classify, claimed, out);
                }
            }
        }
        _ => {}
    }
}

/// Decode a string that is exactly the canonical JSON encoding of a JSON object or array.
/// Used by adapters whose wire format has no marker distinguishing structured content from a
/// plain string: `wrap` refuses plain strings that this would misread, so the mapping is
/// reversible for everything `wrap` accepts.
pub(crate) fn decode_structured_container(text: &str) -> Option<Value> {
    let decoded: Value = serde_json::from_str(text).ok()?;
    if !(decoded.is_object() || decoded.is_array()) {
        return None;
    }
    (canonical_json(&decoded) == text).then_some(decoded)
}

pub(crate) fn validated_model_id(config: &TransportConfig) -> Result<String, RefusalEnvelope> {
    let model_id = config.model_id.trim();
    if model_id.is_empty() {
        return Err(RefusalEnvelope::bad_request(
            "transport config requires a non-empty model_id",
            json!({ "field": "model_id" }),
        ));
    }
    Ok(model_id.to_string())
}

pub(crate) fn validated_temperature(
    config: &TransportConfig,
) -> Result<Option<f64>, RefusalEnvelope> {
    match config.temperature {
        Some(temperature) if !temperature.is_finite() => Err(RefusalEnvelope::bad_request(
            "transport config temperature must be finite",
            json!({ "field": "temperature", "value": temperature.to_string() }),
        )),
        other => Ok(other),
    }
}

pub(crate) fn prompt_messages(prompt_payload: &Value) -> Result<&Vec<Value>, RefusalEnvelope> {
    prompt_payload
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RefusalEnvelope::bad_prompt(
                "prompt payload must contain a messages array",
                json!({ "field": "messages" }),
            )
        })
}

/// A prompt message split into role and content, with anything the vendor wire format cannot
/// carry refused up front instead of emitted as an invalid request.
pub(crate) struct PromptMessage<'a> {
    pub role: &'a str,
    pub content: &'a Value,
}

pub(crate) fn prompt_message<'a>(
    message: &'a Value,
    index: usize,
    allowed_roles: &[&str],
    adapter: &str,
) -> Result<PromptMessage<'a>, RefusalEnvelope> {
    let object = message.as_object().ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must be objects",
            json!({ "field": "messages", "index": index }),
        )
    })?;
    if let Some(extra) = object
        .keys()
        .find(|key| key.as_str() != "role" && key.as_str() != "content")
    {
        return Err(RefusalEnvelope::bad_prompt(
            format!("{adapter} messages carry only role and content"),
            json!({ "field": format!("messages[{index}].{extra}") }),
        ));
    }
    let role = object.get("role").and_then(Value::as_str).ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include a string role",
            json!({ "field": format!("messages[{index}].role") }),
        )
    })?;
    // An empty list means any role is passed through unchanged (the generic adapter).
    if !allowed_roles.is_empty() && !allowed_roles.contains(&role) {
        return Err(RefusalEnvelope::bad_prompt(
            format!("{adapter} does not accept this message role"),
            json!({
                "field": format!("messages[{index}].role"),
                "role": role,
                "allowed": allowed_roles,
            }),
        ));
    }
    let content = object.get("content").ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include content",
            json!({ "field": format!("messages[{index}].content") }),
        )
    })?;
    Ok(PromptMessage { role, content })
}

/// Merge `additional_params` into a request. A key must be one the vendor schema declares and
/// must not replace a field the adapter already set.
pub(crate) fn apply_additional_params(
    request: &mut Map<String, Value>,
    params: Option<&Map<String, Value>>,
    reserved: &[&str],
    allowed: &[&str],
    adapter: &str,
) -> Result<(), RefusalEnvelope> {
    let Some(params) = params else {
        return Ok(());
    };
    for (key, value) in params {
        if reserved.contains(&key.as_str()) || request.contains_key(key) {
            return Err(RefusalEnvelope::bad_request(
                "additional_params may not override reserved request fields",
                json!({ "field": key }),
            ));
        }
        if !allowed.contains(&key.as_str()) {
            return Err(RefusalEnvelope::bad_request(
                format!("additional_params key is not a {adapter} request field"),
                json!({ "field": key, "adapter": adapter }),
            ));
        }
        request.insert(key.clone(), value.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::canonical_json;

    fn sample_prompt_payload() -> Value {
        json!({
            "messages": [
                {"role": "system", "content": "You are a careful boundary verifier."},
                {
                    "role": "user",
                    "content": {
                        "benchmark_summary": {"coverage": 0.98},
                        "challenge_profile": {"page_count": 12}
                    }
                }
            ]
        })
    }

    #[test]
    fn adapter_name_matches_expected_constant() {
        let adapter = OpenAiChatCompletionsAdapter;
        assert_eq!(adapter.name(), OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
    }

    #[test]
    fn wrap_builds_openai_chat_completions_request() {
        let adapter = OpenAiChatCompletionsAdapter;
        let mut additional_params = Map::new();
        additional_params.insert("logprobs".to_string(), json!(true));
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(4096),
            response_format: Some(json!({"type": "json_object"})),
            additional_params: Some(additional_params),
        };

        let request = adapter.wrap(&sample_prompt_payload(), &config).unwrap();

        assert_eq!(request["model"], "gpt-5");
        assert_eq!(request["temperature"], 0.0);
        assert_eq!(request["max_tokens"], 4096);
        assert_eq!(request["response_format"], json!({"type": "json_object"}));
        assert_eq!(request["logprobs"], true);
        assert_eq!(
            request["messages"][0],
            sample_prompt_payload()["messages"][0]
        );
        assert_eq!(
            request["messages"][1]["content"],
            json!([{
                "type": "text",
                "text": r#"{"benchmark_summary":{"coverage":0.98},"challenge_profile":{"page_count":12}}"#
            }])
        );
    }

    #[test]
    fn wrap_preserves_prompt_payload_content_without_injection() {
        let adapter = OpenAiChatCompletionsAdapter;
        let prompt_payload = sample_prompt_payload();
        let config = TransportConfig::new("gpt-5");

        let request = adapter.wrap(&prompt_payload, &config).unwrap();
        let keys = request
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();

        assert_ne!(request["messages"], prompt_payload["messages"]);
        assert_eq!(
            adapter.unwrap(&request).unwrap(),
            sort_value(prompt_payload)
        );
        assert_eq!(keys, vec!["messages", "model"]);
    }

    #[test]
    fn wrap_never_emits_object_message_content() {
        let adapter = OpenAiChatCompletionsAdapter;
        let request = adapter
            .wrap(&sample_prompt_payload(), &TransportConfig::new("gpt-5"))
            .unwrap();

        assert!(
            request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|message| !message["content"].is_object())
        );
    }

    #[test]
    fn unwrap_preserves_string_content_and_decodes_canonical_user_text_part() {
        let adapter = OpenAiChatCompletionsAdapter;
        let prompt = sample_prompt_payload();
        let request = adapter
            .wrap(&prompt, &TransportConfig::new("gpt-5"))
            .unwrap();

        assert_eq!(adapter.unwrap(&request).unwrap(), sort_value(prompt));
    }

    #[test]
    fn unwrap_leaves_noncanonical_user_text_parts_unmodified() {
        let adapter = OpenAiChatCompletionsAdapter;
        let request = json!({
            "model": "gpt-5",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "{ \"a\" : 1 }"}]
            }]
        });

        assert_eq!(
            adapter.unwrap(&request).unwrap()["messages"][0]["content"],
            request["messages"][0]["content"]
        );
    }

    #[test]
    fn wrap_rejects_missing_model_id() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig::new("   ");

        let refusal = adapter.wrap(&sample_prompt_payload(), &config).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_REQUEST");
        assert!(refusal.refusal.message.contains("model_id"));
    }

    #[test]
    fn wrap_rejects_prompt_payload_without_messages_array() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig::new("gpt-5");

        let refusal = adapter
            .wrap(&json!({"user": "missing messages"}), &config)
            .unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_PROMPT");
        assert!(refusal.refusal.message.contains("messages array"));
    }

    #[test]
    fn wrap_rejects_reserved_additional_params() {
        let adapter = OpenAiChatCompletionsAdapter;
        let mut additional_params = Map::new();
        additional_params.insert("messages".to_string(), json!(["should not override"]));
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: None,
            max_tokens: None,
            response_format: None,
            additional_params: Some(additional_params),
        };

        let refusal = adapter.wrap(&sample_prompt_payload(), &config).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_REQUEST");
        assert!(refusal.refusal.message.contains("reserved request fields"));
    }

    #[test]
    fn wrap_returns_canonical_json_key_order() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(1024),
            response_format: Some(json!({"type": "json_object"})),
            additional_params: None,
        };

        let request = adapter.wrap(&sample_prompt_payload(), &config).unwrap();
        let serialized = serde_json::to_string(&request).unwrap();

        assert_eq!(request, sort_value(request.clone()));
        assert_eq!(serialized, canonical_json(&request));
    }

    // -----------------------------------------------------------------------------------------
    // Adapter selection
    // -----------------------------------------------------------------------------------------

    fn selected_name(request: &Value, declared: Option<&TransportDeclaration>) -> String {
        select(request, declared)
            .expect("selection should succeed")
            .name()
            .to_string()
    }

    fn declaration(adapter: &str) -> TransportDeclaration {
        TransportDeclaration {
            adapter: Some(adapter.to_string()),
            ..TransportDeclaration::default()
        }
    }

    fn generic_declaration() -> TransportDeclaration {
        TransportDeclaration {
            adapter: Some(GENERIC_JSON_ADAPTER_NAME.to_string()),
            messages_pointer: Some("/chat".to_string()),
            transport_keys: Some(vec!["chat".to_string(), "model".to_string()]),
            ..TransportDeclaration::default()
        }
    }

    #[test]
    fn detection_follows_the_request_shape() {
        let cases = [
            (
                json!({"model": "m", "messages": [], "max_tokens": 5}),
                OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "messages": [], "temperature": 0.0}),
                OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "messages": [], "max_tokens": 5, "system": "s"}),
                ANTHROPIC_MESSAGES_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "messages": [], "stop_sequences": ["x"]}),
                ANTHROPIC_MESSAGES_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "input": "hi"}),
                OPENAI_RESPONSES_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "input": [{"role": "user", "content": "hi"}]}),
                OPENAI_RESPONSES_ADAPTER_NAME,
            ),
            (
                json!({"model": "m", "contents": []}),
                GEMINI_GENERATE_CONTENT_ADAPTER_NAME,
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(selected_name(&request, None), expected, "{request}");
        }
    }

    #[test]
    fn detection_refuses_instead_of_guessing() {
        let cases = [
            (json!({"model": "m"}), "does not match a known vendor shape"),
            (
                json!({"model": "m", "messages": "not an array"}),
                "does not match a known vendor shape",
            ),
            (
                json!({"model": "m", "messages": [], "input": "x"}),
                "mixes vendor shapes",
            ),
            (
                json!({"model": "m", "messages": [], "contents": []}),
                "mixes vendor shapes",
            ),
            (
                json!({"messages": [], "temperature": 0.0, "system": "s"}),
                "mixes OpenAI Chat Completions and Anthropic Messages fields",
            ),
            (json!(["messages"]), "must be a JSON object"),
        ];
        for (request, expected) in cases {
            let error = select(&request, None)
                .err()
                .expect("selection should refuse");
            assert_eq!(error.refusal.code.as_str(), "E_BAD_REQUEST", "{request}");
            assert!(
                error.refusal.message.contains(expected),
                "{request}: {}",
                error.refusal.message
            );
        }
    }

    #[test]
    fn an_explicit_adapter_wins_over_detection() {
        // The shape says Gemini; the declaration says generic_json, so generic_json it is.
        let gemini_shaped = json!({"model": "m", "contents": [], "chat": []});
        assert_eq!(
            selected_name(&gemini_shaped, Some(&generic_declaration())),
            GENERIC_JSON_ADAPTER_NAME
        );
        // A request that could not be detected at all still selects when declared.
        assert_eq!(
            selected_name(
                &json!({"model": "m"}),
                Some(&declaration(ANTHROPIC_MESSAGES_ADAPTER_NAME))
            ),
            ANTHROPIC_MESSAGES_ADAPTER_NAME
        );
        // An anthropic request detected as Chat (only shared keys) is fixed by declaring it.
        let shared_keys_only = json!({"model": "m", "messages": [], "max_tokens": 5});
        assert_eq!(
            selected_name(&shared_keys_only, None),
            OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME
        );
        assert_eq!(
            selected_name(
                &shared_keys_only,
                Some(&declaration(ANTHROPIC_MESSAGES_ADAPTER_NAME))
            ),
            ANTHROPIC_MESSAGES_ADAPTER_NAME
        );
    }

    #[test]
    fn every_named_adapter_can_be_selected_by_declaration() {
        let request = json!({"model": "m"});
        for name in ADAPTER_NAMES {
            if name == GENERIC_JSON_ADAPTER_NAME {
                continue;
            }
            assert_eq!(selected_name(&request, Some(&declaration(name))), name);
        }
    }

    #[test]
    fn a_declaration_without_an_adapter_falls_back_to_detection() {
        let request = json!({"model": "m", "input": "hi"});
        assert_eq!(
            selected_name(&request, Some(&TransportDeclaration::default())),
            OPENAI_RESPONSES_ADAPTER_NAME
        );
    }

    #[test]
    fn inconsistent_declarations_are_refused() {
        let request = json!({"model": "m", "input": "hi"});

        let unknown = select(&request, Some(&declaration("carrier_pigeon")))
            .err()
            .expect("unknown adapter should refuse");
        assert_eq!(unknown.refusal.code.as_str(), "E_BAD_INPUT");
        assert_eq!(unknown.refusal.detail["supported"], json!(ADAPTER_NAMES));

        let pointers_on_a_vendor_adapter = TransportDeclaration {
            adapter: Some(OPENAI_RESPONSES_ADAPTER_NAME.to_string()),
            messages_pointer: Some("/input".to_string()),
            ..TransportDeclaration::default()
        };
        let error = select(&request, Some(&pointers_on_a_vendor_adapter))
            .err()
            .expect("generic fields on a vendor adapter should refuse");
        assert!(
            error
                .refusal
                .message
                .contains("only to the generic_json adapter")
        );

        let pointers_without_an_adapter = TransportDeclaration {
            messages_pointer: Some("/input".to_string()),
            ..TransportDeclaration::default()
        };
        let error = select(&request, Some(&pointers_without_an_adapter))
            .err()
            .expect("generic fields without an adapter should refuse");
        assert!(error.refusal.message.contains("no adapter"));

        let incomplete_generic = declaration(GENERIC_JSON_ADAPTER_NAME);
        let error = select(&request, Some(&incomplete_generic))
            .err()
            .expect("generic_json needs its pointers");
        assert_eq!(error.refusal.code.as_str(), "E_BAD_INPUT");
    }

    #[test]
    fn transport_declarations_reject_unknown_fields() {
        let parsed: Result<TransportDeclaration, _> =
            serde_json::from_value(json!({"adapter": "openai_responses", "adaptor": "typo"}));
        assert!(parsed.is_err());

        let parsed: TransportDeclaration = serde_json::from_value(json!({
            "adapter": "generic_json",
            "messages_pointer": "/chat",
            "transport_keys": ["chat", "model"],
        }))
        .unwrap();
        assert_eq!(parsed.messages_pointer.as_deref(), Some("/chat"));
    }

    // -----------------------------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------------------------

    #[test]
    fn pointers_escape_reference_tokens() {
        assert_eq!(pointer_child("", "a/b"), "/a~1b");
        assert_eq!(pointer_child("/x", "c~d"), "/x/c~0d");
        assert_eq!(pointer_index("/x", 3), "/x/3");
    }

    #[test]
    fn references_classify_data_uris_and_urls() {
        let base64 = classify_reference("/p".to_string(), "data:image/png;base64,AAAA");
        assert_eq!(
            base64.kind,
            PartKind::Base64Media {
                media_type: "image/png".to_string()
            }
        );
        assert_eq!(base64.data, "AAAA");

        // A data URI without `;base64` is not binary media: keep the whole string to screen.
        let plain = classify_reference("/p".to_string(), "data:text/plain,hello");
        assert_eq!(plain.kind, PartKind::RemoteReference);
        assert_eq!(plain.data, "data:text/plain,hello");

        let remote = classify_reference("/p".to_string(), "https://example.com/a.png");
        assert_eq!(remote.kind, PartKind::RemoteReference);

        let bare = classify_inline_file("/p".to_string(), "JVBERi0=");
        assert_eq!(
            bare.kind,
            PartKind::Base64Media {
                media_type: "application/octet-stream".to_string()
            }
        );
    }

    #[test]
    fn structured_containers_decode_only_from_canonical_json() {
        assert_eq!(
            decode_structured_container(r#"{"a":[1,2]}"#),
            Some(json!({"a": [1, 2]}))
        );
        assert_eq!(decode_structured_container("[1,2]"), Some(json!([1, 2])));
        for not_canonical in [
            r#"{"b":1,"a":2}"#,
            r#"{ "a": 1 }"#,
            "42",
            "true",
            "null",
            r#""text""#,
            "plain words",
            "",
        ] {
            assert_eq!(
                decode_structured_container(not_canonical),
                None,
                "{not_canonical}"
            );
        }
    }

    #[test]
    fn prompt_messages_refuse_what_a_wire_format_cannot_carry() {
        let roles = ["user", "assistant"];
        let ok = json!({"role": "user", "content": "hi"});
        assert_eq!(prompt_message(&ok, 0, &roles, "Test").unwrap().role, "user");

        let cases = [
            (json!("not an object"), "must be objects"),
            (json!({"role": "user"}), "must include content"),
            (json!({"content": "hi"}), "must include a string role"),
            (
                json!({"role": 7, "content": "hi"}),
                "must include a string role",
            ),
            (
                json!({"role": "user", "content": "hi", "name": "n"}),
                "carry only role and content",
            ),
            (
                json!({"role": "tool", "content": "hi"}),
                "does not accept this message role",
            ),
        ];
        for (message, expected) in cases {
            let error = prompt_message(&message, 0, &roles, "Test")
                .err()
                .expect("message should be refused");
            assert_eq!(error.refusal.code.as_str(), "E_BAD_PROMPT", "{message}");
            assert!(
                error.refusal.message.contains(expected),
                "{message}: {}",
                error.refusal.message
            );
        }

        // An empty role list means any role is passed through.
        let any_role = json!({"role": "tool", "content": "hi"});
        assert!(prompt_message(&any_role, 0, &[], "Test").is_ok());
    }

    #[test]
    fn additional_params_are_checked_against_reserved_and_declared_keys() {
        let params = |value: Value| value.as_object().cloned();
        let mut request = Map::new();
        request.insert("model".to_string(), json!("m"));

        apply_additional_params(
            &mut request,
            params(json!({"seed": 7})).as_ref(),
            &["model"],
            &["model", "seed"],
            "Test",
        )
        .unwrap();
        assert_eq!(request["seed"], 7);

        let reserved = apply_additional_params(
            &mut request,
            params(json!({"model": "other"})).as_ref(),
            &["model"],
            &["model", "seed"],
            "Test",
        )
        .unwrap_err();
        assert!(reserved.refusal.message.contains("reserved request fields"));
        assert_eq!(request["model"], "m");

        let undeclared = apply_additional_params(
            &mut request,
            params(json!({"nope": 1})).as_ref(),
            &["model"],
            &["model", "seed"],
            "Test",
        )
        .unwrap_err();
        assert!(
            undeclared
                .refusal
                .message
                .contains("not a Test request field")
        );
        assert!(request.get("nope").is_none());
    }

    // -----------------------------------------------------------------------------------------
    // Chat Completions screenable parts
    // -----------------------------------------------------------------------------------------

    #[test]
    fn chat_extraction_classifies_media_and_reports_every_other_string() {
        let request = json!({
            "model": "gpt-5",
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": [
                    {"type": "text", "text": "look"},
                    {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,/9j/4A==", "detail": "low"}},
                    {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
                    {"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "mp3"}},
                    {"type": "file", "file": {"file_id": "file-1", "filename": "a.pdf"}}
                ]},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{\"q\":\"x\"}"}}
                ]}
            ]
        });
        let parts = OpenAiChatCompletionsAdapter
            .extract_screenable_parts(&request)
            .unwrap();
        let find = |pointer: &str| parts.iter().find(|part| part.pointer == pointer);

        assert_eq!(
            find("/messages/1/content/1/image_url/url").unwrap().kind,
            PartKind::Base64Media {
                media_type: "image/jpeg".to_string()
            }
        );
        assert_eq!(
            find("/messages/1/content/1/image_url/url").unwrap().data,
            "/9j/4A=="
        );
        assert_eq!(
            find("/messages/1/content/2/image_url/url").unwrap().kind,
            PartKind::RemoteReference
        );
        assert_eq!(
            find("/messages/1/content/3/input_audio/data").unwrap().kind,
            PartKind::Base64Media {
                media_type: "audio/mp3".to_string()
            }
        );
        assert_eq!(
            find("/messages/1/content/4/file/file_id").unwrap().kind,
            PartKind::RemoteReference
        );
        for text in [
            "/model",
            "/messages/1/content/1/image_url/detail",
            "/messages/1/content/4/file/filename",
            "/messages/2/tool_calls/0/function/arguments",
            "/messages/2/tool_calls/0/id",
            "/messages/2/tool_calls/0/type",
        ] {
            assert_eq!(
                find(text).map(|part| &part.kind),
                Some(&PartKind::Text),
                "{text}"
            );
        }
        // `content: null` carries no string, so nothing is reported for it.
        assert!(find("/messages/2/content").is_none());
    }

    #[test]
    fn extraction_refuses_a_request_that_is_not_an_object() {
        let error = OpenAiChatCompletionsAdapter
            .extract_screenable_parts(&json!("text"))
            .unwrap_err();
        assert_eq!(error.refusal.code.as_str(), "E_BAD_REQUEST");
    }

    #[test]
    fn walker_does_not_report_a_claimed_payload_twice() {
        // A classifier that claims one string in an object it recognises: the walker reports
        // the claim once and every other string in the object as text.
        let classify =
            |object: &Map<String, Value>, pointer: &str, out: &mut Vec<ScreenablePart>| {
                if object.contains_key("blob") {
                    out.push(ScreenablePart {
                        pointer: pointer_child(pointer, "blob"),
                        kind: PartKind::Base64Media {
                            media_type: "x/y".to_string(),
                        },
                        data: "AAAA".to_string(),
                    });
                    return true;
                }
                false
            };
        let request = json!({"item": {"blob": "AAAA", "label": "named"}, "other": ["z"]});
        let parts = walk_request(&request, &classify).unwrap();

        let mut rows: Vec<(String, bool)> = parts
            .iter()
            .map(|part| (part.pointer.clone(), part.kind == PartKind::Text))
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("/item/blob".to_string(), false),
                ("/item/label".to_string(), true),
                ("/other/0".to_string(), true),
            ]
        );
    }
}
