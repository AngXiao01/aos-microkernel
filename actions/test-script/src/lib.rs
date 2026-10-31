//! A scripted action for the runtime tests: input `script` is a list of operations, each a
//! map with an `op` key, performed in order through the host ABI. The same module, loaded
//! with different declarations and capabilities, exercises every check the runtime makes.
//!
//! A failing operation `i` makes `run` return `100 + 10 * i` plus the host error's
//! magnitude, so tests can tell which step failed and why.

#![no_std]

extern crate alloc;

use aos_action_sdk::aos_types::cbor::{Cbor, CborMap};
use aos_action_sdk::aos_types::{FromCbor, Object};
use aos_action_sdk::{self as sdk, HostError, map};

sdk::action!(script);

fn get<'a>(m: &'a CborMap, key: &str) -> Result<&'a Cbor, i32> {
    m.get_str(key).ok_or(2)
}

fn text<'a>(m: &'a CborMap, key: &str) -> Result<&'a str, i32> {
    get(m, key)?.as_text().ok_or(3)
}

fn fields(m: &CborMap) -> Result<Cbor, i32> {
    Ok(Cbor::Map(map([("n", get(m, "n")?.clone())])))
}

fn version_of(id: &Cbor) -> Result<u64, HostError> {
    let object = Object::from_cbor(&sdk::read(map([("id", id.clone())]))?).map_err(|_| HostError(-90))?;
    Ok(object.version)
}

fn step(m: &CborMap) -> Result<(), StepError> {
    match text(m, "op")? {
        "read" => {
            sdk::read(map([("id", get(m, "id")?.clone())]))?;
        }
        "write" => {
            let id = get(m, "id")?;
            let version = version_of(id)?;
            sdk::write(map([
                ("id", id.clone()),
                ("expected_version", Cbor::Unsigned(version)),
                ("fields", fields(m)?),
            ]))?;
        }
        "delete" => {
            let id = get(m, "id")?;
            let version = version_of(id)?;
            sdk::delete(map([("id", id.clone()), ("expected_version", Cbor::Unsigned(version))]))?;
        }
        "create" => {
            let created = sdk::create(map([("type", Cbor::text(text(m, "type")?)), ("fields", fields(m)?)]))?;
            sdk::output(map([("created", created.as_map().and_then(|c| c.get_str("id")).cloned().ok_or(4)?)]));
        }
        "query" => {
            let found = sdk::query(map([("from", Cbor::text(text(m, "type")?))]))?;
            let count = found.as_array().map_or(0, <[Cbor]>::len) as u64;
            if m.get_str("expect").and_then(Cbor::as_u64).is_some_and(|e| e != count) {
                return Err(StepError::Code(5));
            }
        }
        "intent" | "job" => {
            let request = map([
                ("channel", Cbor::text(text(m, "channel")?)),
                ("target", Cbor::text("test://target")),
                ("summary", Cbor::text("scripted")),
            ]);
            if text(m, "op")? == "intent" {
                sdk::intent_create(request)?
            } else {
                sdk::job_submit(request)?
            };
        }
        "blob" => {
            let data = get(m, "data")?.as_bytes().ok_or(6)?;
            let hash = sdk::blob_write(data)?;
            if sdk::blob_read(hash, 0, data.len() as u64)? != data {
                return Err(StepError::Code(7));
            }
        }
        "output" => sdk::output(get(m, "value")?.as_map().ok_or(8)?.clone()),
        "log" => sdk::log(1, text(m, "message")?),
        "fail" => return Err(StepError::Code(9)),
        "spin" => loop {
            core::hint::black_box(0u32);
        },
        "trap" => core::arch::wasm32::unreachable(),
        _ => return Err(StepError::Code(1)),
    }
    Ok(())
}

enum StepError {
    Code(i32),
    Host(HostError),
}

impl From<i32> for StepError {
    fn from(code: i32) -> StepError {
        StepError::Code(code)
    }
}

impl From<HostError> for StepError {
    fn from(e: HostError) -> StepError {
        StepError::Host(e)
    }
}

fn script(inputs: CborMap) -> Result<(), i32> {
    let ops = inputs.get_str("script").and_then(Cbor::as_array).ok_or(10)?;
    for (i, op) in ops.iter().enumerate() {
        let base = 100 + 10 * i as i32;
        match step(op.as_map().ok_or(11)?) {
            Ok(()) => {}
            Err(StepError::Code(c)) => return Err(base + c),
            Err(StepError::Host(HostError(e))) => return Err(base - e),
        }
    }
    Ok(())
}
