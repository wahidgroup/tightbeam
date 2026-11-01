use std::sync::Arc;

use tightbeam::{job, prelude::TightBeamSocketAddr, Frame, TightBeamError};

use crate::dtn::jobs::GapRecoveryContext;

job! {
	/// Sends a frame to the upstream hop through the pool of the context, and
	/// returns the reply of the hop.
	name: EmitFrameToNetwork,
	async fn run(
		(frame, addr, ctx): (Frame, TightBeamSocketAddr, Arc<GapRecoveryContext>),
	) -> Result<Option<Frame>, TightBeamError> {
		let mut client = ctx.pool.connect(addr).await?;
		Ok(client.conn()?.emit(frame, None).await?)
	}
}
