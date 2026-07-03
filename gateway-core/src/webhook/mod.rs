//! Webhook delivery: the fan-out spine and per-subscription delivery state.
//!
//! # Two stages
//!
//! A state change appends a durable `subject_event` and a `delivery_outbox` row
//! in the writer's transaction (see [`crate::events`]). The outbox row is the
//! durable record that an event happened and is ready to fan out. The webhook
//! fan-out stage drains the outbox as a *set*, exploding each un-fanned row into
//! one [`webhook_delivery`] row per matching subscription. The two stages keep
//! per-subscription delivery state (`webhook_delivery`) separate from the shared
//! event spine (`delivery_outbox`), so one slow endpoint never blocks another
//! subscriber of the same event and subscriptions can be added or removed without
//! rewriting history.
//!
//! [`webhook_delivery`]: fanout
//!
//! # Presence-based fan-out (no cursor)
//!
//! [`fanout`] drains `delivery_outbox` rows whose `fanned_out_at IS NULL` as a
//! set: the order within a drain pass does not affect completeness, because every
//! un-fanned row is visited on some pass and stamped exactly once. There is no
//! global ordering key and no cursor. The mid-stream-subscribe boundary falls out
//! of this directly: the fan-out reader matches an outbox row only against the
//! subscriptions that exist when it explodes that row, then stamps the row, so a
//! subscription created at time T receives exactly the events fanned out after it
//! commits. A sequence cursor over the outbox is the rejected alternative: a
//! rolled-back allocation leaves a permanent gap a gap-free high-water waits on
//! forever (a wedge), and a late out-of-order commit is stepped past by a
//! gap-skipping high-water (a miss). Presence (NULL vs stamped) has neither
//! failure mode.

pub mod delivery;
pub mod egress;
pub mod fanout;
pub mod owner;
pub mod projection;
pub mod registration;
pub mod secret;
pub mod signer;
pub mod worker;

pub use delivery::{
    claim_due, explode_outbox_row, load_for_delivery, record_failure, record_success,
    release_for_custody_retry, ClaimedDelivery, DeliveryPolicy, FailureOutcome,
};
pub use egress::{deliver, DeliveryError, DeliveryResponse, EgressConfig};
pub use fanout::{claim_unfanned, stamp_fanned_out, ClaimedOutboxRow};
pub use owner::{resolve_owner, OwnerResolution, SubjectOwner};
pub use projection::{
    build_envelope, delivery_id, project_event, project_wire_event, WireEvent, WireVisibility,
};
// Internal to the crate: shared by the SSE stream so a record event's and an
// account event's `data` body is built identically on both transports.
pub(crate) use projection::{build_account_event_data, build_poe_event_data};
pub use registration::{
    commit_rotation, create_endpoint, get_endpoint, list_deliveries, list_endpoints,
    patch_endpoint, retry_delivery, rotate_secret, soft_delete_endpoint, CreatedEndpoint,
    DeliveryView, EndpointChange, EndpointPatch, EndpointScope, EndpointStatus, EndpointView,
    NewEndpoint, RedriveOutcome, RotatedSecret,
};
pub use secret::SecretWrap;
pub use signer::{sign_delivery, sign_v1, SignedHeaders, WEBHOOK_USER_AGENT};
pub use worker::{
    delivery_policy, delivery_schedule, fanout_policy, fanout_schedule, wake_delivery, wake_fanout,
    DeliveryHandler, FanoutHandler, DELIVERY_QUEUE, FANOUT_QUEUE,
};
