//! Replay the shared replay-clock vectors through the installed Rust SDK.
//!
//! Reads vectors-v1.json from the path in argv[1] and prints one JSON object
//! mapping each case id to its observations. Times are UTC RFC 3339 with six
//! fractional digits and Z; an unavailable read is null.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use durable_workflow::testing::{WorkflowEnvironment, WorkflowHistory};
use durable_workflow::{Client, Error, Worker, WorkflowContext};
use serde_json::{json, Map, Value};

/// Carriers the offline history builder refuses up front: another run's
/// carrier and a low-precision `started_at`. Every other carrier is accepted
/// by the builder; an unproved one (the redrive source on ordinary history)
/// is then left absent during replay.
const BUILDER_REFUSES: [&str; 2] = ["carrier-for-another-run", "carrier-low-precision"];

/// Only an unavailable clock is reported as null; any other error fails the run.
fn read(ctx: &WorkflowContext) -> Result<Value, Error> {
    match ctx.replay_now() {
        Ok(time) => Ok(json!(time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))),
        Err(Error::ReplayClockUnavailable) => Ok(Value::Null),
        Err(error) => Err(error),
    }
}

fn micros(text: &Value) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(text.as_str()?).ok()?;
    Some(parsed.timestamp_micros())
}

fn main() {
    let path = std::env::args().nth(1).expect("vectors path");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json");
    let spec = vectors["workflow"].clone();
    let seen: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));

    let mut worker = Worker::new(Client::new("http://127.0.0.1:9").expect("client"), "conformance");
    let (activity, seconds) = (spec["activity_type"].as_str().unwrap().to_owned(), spec["timer_seconds"].as_u64().unwrap());
    let sink = seen.clone();
    worker.register_workflow(spec["type"].as_str().unwrap(), move |ctx: WorkflowContext, _args: Value| {
        let (activity, sink) = (activity.clone(), sink.clone());
        async move {
            let entry = read(&ctx)?;
            let repeated = read(&ctx)? == entry;
            ctx.activity(activity, json!([])).await?;
            let after_activity = read(&ctx)?;
            ctx.sleep(Duration::from_secs(seconds)).await?;
            let after_timer = read(&ctx)?;
            let observed = json!({"entry":entry,"repeated_reads_equal":repeated,
                "after_activity":after_activity,"after_timer":after_timer});
            *sink.lock().unwrap() = Some(observed.clone());
            Ok(observed)
        }
    });
    let environment = WorkflowEnvironment::from_worker(worker);

    let mut observations = Map::new();
    for case in vectors["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let history = WorkflowHistory::from_history(
            spec["type"].as_str().unwrap(),
            (),
            json!({"workflow_id":spec["workflow_id"],"run_id":spec["run_id"],"events":vectors["history"]}),
        )
        .expect("history");
        // The builder refuses only the other-run and low-precision carriers;
        // replay then runs without one, the same absence a worker applies.
        let history = match case.get("replay_clock") {
            Some(carrier) if BUILDER_REFUSES.contains(&id) => {
                let refused = history.clone().replay_clock(carrier.clone());
                assert!(refused.is_err(), "{id}: the builder accepted a carrier it must refuse");
                history
            }
            Some(carrier) => history
                .replay_clock(carrier.clone())
                .unwrap_or_else(|error| panic!("{id}: carrier refused: {error}")),
            None => history,
        };
        *seen.lock().unwrap() = None;
        let report = environment.replay(&history).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(report.completed, "{id}: replay did not complete");
        let mut observed = seen.lock().unwrap().take().unwrap_or_else(|| panic!("{id}: no observation"));
        let elapsed = match (micros(&observed["after_activity"]), micros(&observed["after_timer"])) {
            (Some(start), Some(end)) => json!(end - start),
            _ => Value::Null,
        };
        observed["elapsed_microseconds"] = elapsed;
        observations.insert(id.to_owned(), observed);
    }
    println!("{}", json!({"binding":"rust","sdk_version":std::env::var("DW_RUST_SDK_VERSION").unwrap_or_default(),
        "observations":observations}));
}
