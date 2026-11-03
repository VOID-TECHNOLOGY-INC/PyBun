use super::{model::*, state::*};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
impl EventReplayCursor {
    pub fn origin(registration: &Registration) -> Self {
        Self::encode(&registration.monitor_id, &registration.epoch_id, 0)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn parse(value: &str) -> MonitorResult<Self> {
        let cursor = Self(value.into());
        cursor.decode()?;
        Ok(cursor)
    }
    pub(crate) fn encode(monitor: &str, epoch: &str, sequence: u64) -> Self {
        Self(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&CursorData {
                    cursor_version: 1,
                    monitor_id: monitor.into(),
                    epoch_id: epoch.into(),
                    sequence,
                })
                .unwrap_or_default(),
            ),
        )
    }
    pub(crate) fn decode(&self) -> MonitorResult<CursorData> {
        if self.0.len() > 2048 {
            return Err(MonitorError::new("E_MONITOR_CURSOR_SCOPE"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.0)
            .map_err(|_| MonitorError::new("E_MONITOR_CURSOR_SCOPE"))?;
        let value: CursorData = serde_json::from_slice(&bytes)
            .map_err(|_| MonitorError::new("E_MONITOR_CURSOR_SCOPE"))?;
        if value.cursor_version != 1 || !valid_id(&value.monitor_id) || !valid_id(&value.epoch_id) {
            return Err(MonitorError::new("E_MONITOR_CURSOR_SCOPE"));
        }
        Ok(value)
    }
}
pub(crate) fn page(
    snapshot: &Snapshot,
    after: Option<&EventReplayCursor>,
) -> MonitorResult<ReplayPage> {
    let events: Vec<_> = snapshot
        .events
        .iter()
        .filter(|event| event.epoch_id == snapshot.epoch_id)
        .collect();
    let low = events
        .first()
        .map_or(snapshot.sequence.saturating_add(1), |event| event.sequence);
    let origin = EventReplayCursor::encode(&snapshot.monitor_id, &snapshot.epoch_id, 0);
    let resync = EventReplayCursor::encode(
        &snapshot.monitor_id,
        &snapshot.epoch_id,
        if low == snapshot.epoch_first_sequence {
            0
        } else {
            low.saturating_sub(1)
        },
    );
    let mut page = ReplayPage {
        events: vec![],
        origin_cursor: origin.clone(),
        resync_cursor: resync,
        next_cursor: None,
        low_water_mark: low,
        high_water_mark: snapshot.sequence,
        has_more: false,
        current: snapshot.summary(),
    };
    let data = after.map(EventReplayCursor::decode).transpose();
    let mut error = None;
    let sequence = match data {
        Ok(Some(cursor))
            if cursor.monitor_id == snapshot.monitor_id
                && cursor.epoch_id == snapshot.epoch_id
                && cursor.sequence <= snapshot.sequence
                && (cursor.sequence == 0 || cursor.sequence >= snapshot.epoch_first_sequence) =>
        {
            let start = if cursor.sequence == 0 {
                snapshot.epoch_first_sequence.saturating_sub(1)
            } else {
                cursor.sequence
            };
            if start.saturating_add(1) < low {
                error = Some("E_MONITOR_CURSOR_EXPIRED");
            }
            start
        }
        Ok(None) => low.saturating_sub(1),
        _ => {
            error = Some("E_MONITOR_CURSOR_SCOPE");
            0
        }
    };
    if let Some(code) = error {
        let mut error = MonitorError::new(code);
        error.replay = Some(Box::new(page));
        return Err(error);
    }
    let remaining: Vec<_> = events
        .into_iter()
        .filter(|event| event.sequence > sequence)
        .collect();
    page.has_more = remaining.len() > REPLAY_PAGE_SIZE;
    page.events = remaining
        .into_iter()
        .take(REPLAY_PAGE_SIZE)
        .cloned()
        .collect();
    page.next_cursor = page
        .events
        .last()
        .map(|event| EventReplayCursor::encode(&event.monitor_id, &event.epoch_id, event.sequence))
        .or_else(|| after.cloned());
    Ok(page)
}

/// Registry-first configuration deliberately hides the previous epoch entirely.
pub(crate) fn pending(
    registration: &Registration,
    after: Option<&EventReplayCursor>,
) -> MonitorError {
    let origin = EventReplayCursor::origin(registration);
    let wrong_scope = after.is_some_and(|cursor| {
        cursor.decode().map_or(true, |value| {
            value.monitor_id != registration.monitor_id
                || value.epoch_id != registration.epoch_id
                || value.sequence != 0
        })
    });
    let mut error = MonitorError::new(if wrong_scope {
        "E_MONITOR_CURSOR_SCOPE"
    } else {
        "E_MONITOR_BASELINE_REQUIRED"
    });
    error.replay = Some(Box::new(ReplayPage {
        events: vec![],
        origin_cursor: origin.clone(),
        resync_cursor: origin,
        next_cursor: None,
        low_water_mark: 1,
        high_water_mark: 0,
        has_more: false,
        current: MonitorSummary {
            monitor_id: registration.monitor_id.clone(),
            epoch_id: registration.epoch_id.clone(),
            config_revision: registration.config_revision,
            generation: 0,
            initialized: false,
            complete: false,
            observed_at: 0,
            findings: vec![],
            diagnostics: vec![MonitorDiagnostic {
                code: "E_MONITOR_BASELINE_REQUIRED".into(),
                scope: "current_epoch".into(),
            }],
        },
    }));
    error
}
