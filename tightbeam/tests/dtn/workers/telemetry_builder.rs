//! The worker that builds the rover's telemetry messages.

use tightbeam::{worker, TightBeamError};

use super::messages::TelemetryBuildRequest;
use crate::dtn::messages::RoverTelemetry;

worker! {
	name: TelemetryBuilderWorker<TelemetryBuildRequest, Result<RoverTelemetry, TightBeamError>>,
	config: {
		default_battery: u8,
		default_temp: i8,
	},
	handle: |request, _trace, config| async move {
		Ok(RoverTelemetry::new(
			request.instrument,
			request.data.as_bytes(),
			request.mission_time_ms,
			config.default_battery,
			config.default_temp,
		)?)
	}
}
