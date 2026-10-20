//! Complete per-call preflight, not worker admission, cancellation or a kernel
//! I/O deadline. Sequential bounded calls remain independent task continuations.
use super::{
    Action, CODE_INVALID_ACTION, PicoclawErrorData, build_hotkey_report, hid, mouse_button,
    normalize_hotkey_keys, normalized_nested_point, normalized_point,
};
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};
use std::{fmt, time::Duration};

pub(super) const MAX_ACTIONS: usize = 64;
const MAX_WAIT_MS: i32 = 5_000;
const MAX_SCROLL: i32 = 100;
const MAX_TYPE_BYTES: usize = 4_096;
const MAX_DELAY: Duration = Duration::from_secs(30);

pub(super) enum PreparedAction {
    Click {
        point: (f64, f64),
        button: u8,
    },
    Move {
        point: (f64, f64),
    },
    Wait(Duration),
    Drag {
        from: (f64, f64),
        to: (f64, f64),
        button: u8,
    },
    Scroll {
        point: (f64, f64),
        amount: u16,
        wheel: i8,
    },
    Type(Vec<[u8; 8]>),
    Hotkey([u8; 8]),
}

pub(super) struct Batch {
    actions: Vec<PreparedAction>,
    result_action: String,
}

fn invalid(message: &'static str) -> PicoclawErrorData {
    PicoclawErrorData::new(CODE_INVALID_ACTION, message)
}

impl Batch {
    /// Expose only an immutable view of the completely validated sequence.
    pub(super) fn parts(&self) -> (&[PreparedAction], &str) {
        (&self.actions, &self.result_action)
    }

    pub(super) fn prepare(raw: Vec<Action>) -> Result<Self, PicoclawErrorData> {
        if raw.is_empty() || raw.len() > MAX_ACTIONS {
            return Err(invalid("a batch requires 1 to 64 actions"));
        }
        if raw.len() == 1 && raw[0].action.len() > 64 {
            return Err(invalid("invalid action name").with_index(0));
        }
        let result_action = if raw.len() > 1 {
            "batch".to_string()
        } else {
            raw[0].action.clone()
        };
        let mut actions = Vec::with_capacity(raw.len());
        let mut typed_bytes = 0_usize;
        let mut delay = Duration::ZERO;
        for (index, action) in raw.into_iter().enumerate() {
            let result = prepare_action(&action, &mut typed_bytes).and_then(|(prepared, cost)| {
                delay = delay
                    .checked_add(cost)
                    .filter(|total| *total <= MAX_DELAY)
                    .ok_or_else(|| invalid("batch scheduled delay exceeds 30 seconds"))?;
                Ok(prepared)
            });
            actions.push(result.map_err(|error| error.with_index(index))?);
        }
        Ok(Self {
            actions,
            result_action,
        })
    }
}

fn prepare_action(
    action: &Action,
    typed_bytes: &mut usize,
) -> Result<(PreparedAction, Duration), PicoclawErrorData> {
    if action.action.len() > 64 {
        return Err(invalid("invalid action name"));
    }
    let name = action.action.trim();
    let (prepared, cost) = if name.eq_ignore_ascii_case("click") {
        (
            PreparedAction::Click {
                point: normalized_point(action.x, action.y)?,
                button: mouse_button(&action.button)?,
            },
            super::DEFAULT_CLICK_HOLD,
        )
    } else if name.eq_ignore_ascii_case("move") {
        (
            PreparedAction::Move {
                point: normalized_point(action.x, action.y)?,
            },
            Duration::ZERO,
        )
    } else if name.eq_ignore_ascii_case("wait") {
        if !(0..=MAX_WAIT_MS).contains(&action.duration_ms) {
            return Err(invalid("wait duration must be between 0 and 5000 ms"));
        }
        let duration = Duration::from_millis(action.duration_ms as u64);
        (PreparedAction::Wait(duration), duration)
    } else if name.eq_ignore_ascii_case("drag") {
        (
            PreparedAction::Drag {
                from: normalized_nested_point(action.from.as_ref())?,
                to: normalized_nested_point(action.to.as_ref())?,
                button: mouse_button(&action.button)?,
            },
            Duration::ZERO,
        )
    } else if name.eq_ignore_ascii_case("scroll") {
        let amount = if action.amount == 0 { 1 } else { action.amount };
        if !(1..=MAX_SCROLL).contains(&amount) {
            return Err(invalid("scroll amount must be between 1 and 100"));
        }
        let direction = action.direction.trim();
        let wheel = if direction.is_empty() || direction.eq_ignore_ascii_case("up") {
            1
        } else if direction.eq_ignore_ascii_case("down") {
            -1
        } else {
            return Err(invalid("invalid scroll direction"));
        };
        let point = if action.x.is_some() || action.y.is_some() {
            normalized_point(action.x, action.y)?
        } else {
            (0.5, 0.5)
        };
        (
            PreparedAction::Scroll {
                point,
                amount: amount as u16,
                wheel,
            },
            super::DEFAULT_SCROLL_STEP * amount as u32,
        )
    } else if name.eq_ignore_ascii_case("type") {
        *typed_bytes = typed_bytes
            .checked_add(action.text.len())
            .filter(|bytes| *bytes <= MAX_TYPE_BYTES)
            .ok_or_else(|| invalid("batch typing exceeds 4096 UTF-8 bytes"))?;
        if action.text.is_empty() {
            return Err(invalid("type requires text"));
        }
        let reports = hid::prepare_type_text(&action.text, "")
            .map_err(|error| PicoclawErrorData::new(CODE_INVALID_ACTION, error.to_string()))?;
        let cost = hid::PASTE_KEY_DELAY * reports.len() as u32;
        (PreparedAction::Type(reports), cost)
    } else if name.eq_ignore_ascii_case("hotkey") {
        // Bound normalization before allocating an arbitrary modifier list.
        match action.keys.as_ref() {
            Some(serde_json::Value::Array(keys))
                if keys.len() <= 14
                    && keys
                        .iter()
                        .all(|key| key.as_str().is_some_and(|key| key.len() <= 64)) => {}
            Some(serde_json::Value::String(keys))
                if keys.len() <= 1024 && keys.split(',').count() <= 14 => {}
            _ => return Err(invalid("hotkey requires at most 14 bounded key names")),
        }
        let keys = normalize_hotkey_keys(action.keys.as_ref())?;
        (
            PreparedAction::Hotkey(build_hotkey_report(&keys)?),
            super::DEFAULT_CLICK_HOLD,
        )
    } else {
        return Err(invalid("unknown or invalid action"));
    };
    Ok((prepared, cost))
}

pub(super) fn deserialize_actions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Action>, D::Error> {
    struct Actions;
    impl<'de> Visitor<'de> for Actions {
        type Value = Vec<Action>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of at most 64 actions")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
            let mut actions =
                Vec::with_capacity(sequence.size_hint().unwrap_or(MAX_ACTIONS).min(MAX_ACTIONS));
            while actions.len() < MAX_ACTIONS {
                let Some(action) = sequence.next_element::<Action>()? else {
                    return Ok(actions);
                };
                actions.push(action);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("a batch supports at most 64 actions"));
            }
            Ok(actions)
        }
    }
    deserializer.deserialize_seq(Actions)
}

pub(super) fn deserialize_present_actions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<Action>>, D::Error> {
    deserialize_actions(deserializer).map(Some)
}

#[cfg(test)]
#[path = "picoclaw_action_plan_tests.rs"]
mod tests;
