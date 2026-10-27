//! Paywall lottery integration tests.
//!
//! The tests run the full metered-service story on the real TCP and pool
//! stack. The lottery serves draws only after these steps:
//! 1. A client connects.
//! 2. The house presents an invoice, the settlement challenge bound into the budget-bearing session receipt.
//! 3. The client countersigns the invoice to pay.
//!
//! Credits are draws: every ticket debits one session-budget credit, so the
//! negotiated budget is the number of draws a paid invoice buys.
//!
//! The house rigs the draw per scenario: the reply repeats the client's pick
//! (a win) or differs from it (the house keeps the pot), so settlement,
//! budget, renewal, and refusal become observable lottery outcomes.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "testing",
	feature = "instrument"
))]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::{CanonicalKey, CertificateSpec};
use tightbeam::decode;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::policy::SessionContext;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, MuxSettings, TransportAuthorizer, TransportOffer,
	SETTLEMENT_UNSUPPORTED_CODE,
};
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};
use tokio::task::JoinHandle;

use crate::common::security::{
	expectation_failure, pinning_trust_store, random_signing_key, test_certificate, PayingApprover, ServerMaterials,
};
use crate::transport::support::{await_transport, bind_mutual_listener};

use tightbeam::instrumentation::events;

/// The invoice the house binds into every budget-bearing receipt.
const LOTTERY_INVOICE: &[u8] = b"lottery-invoice-one-credit-per-draw";

/// The payment preimage a client countersigns the invoice with to pay.
const LOTTERY_PAYMENT: &[u8] = b"lottery-payment-preimage";

/// The application code for an unpaid or short-paid invoice.
const INVOICE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 40;

/// The application code a broke client refuses a renewal invoice with.
const WALLET_EMPTY_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 41;

/// The pick every gambler plays.
const LUCKY_NUMBER: &str = "123";

/// The client-to-server credits a paid invoice buys. With one-credit
/// tickets, that is exactly the number of draws.
const DRAW_CREDITS: u64 = 10;

/// The client-view settings the lottery negotiation lands on: both sides offer
/// `mux(1)` with 1 KiB chunks, and the house grants the requested draw budget.
fn lottery_settings() -> MuxSettings {
	let mut settings = MuxSettings::symmetric(1);
	settings.send_chunk_size = 1024;
	settings.recv_chunk_size = 1024;
	settings.send_budget = Some(DRAW_CREDITS);
	settings
}

/// The draws served against the initial invoice before the budget watermark
/// opens a renewal, a top-up invoice, for the rest. The value is
/// `MuxSettings::usable_send_budget`, the watermark math the mux enforces.
fn prepaid_draws() -> u64 {
	lottery_settings().usable_send_budget().unwrap_or_default()
}

/// The announcement for a draw against an empty ledger account.
const ACCOUNT_EMPTY: &str = "account-empty";

/// The draws spent on the first connection of the reconnect scenario.
const OPENING_DRAWS: u64 = 3;

/// How the house rigs each draw against the client's pick.
#[derive(Clone, Copy)]
enum DrawRig {
	/// The reply repeats the pick: the client always wins.
	AlwaysWin,
	/// The reply differs from the pick: the house keeps the pot.
	HouseAlwaysWins,
}

impl DrawRig {
	/// The number the house announces for `pick`.
	fn outcome(self, pick: impl AsRef<str>) -> String {
		let pick = pick.as_ref();
		match self {
			Self::AlwaysWin => pick.to_owned(),
			Self::HouseAlwaysWins => format!("house-keeps-{pick}"),
		}
	}
}

fn lottery_offer() -> Option<TransportOffer> {
	let budgets = MuxBudgets { client_to_server: DRAW_CREDITS, server_to_client: 4096 };
	let offer = TransportOffer::mux(1).with_chunk_payload_size(1024).with_budgets(budgets);
	Some(offer)
}

/// The offer for ledger-metered sessions. Session budgets stay generous, so
/// the durable account ledger is the only meter in play.
fn ledger_offer() -> Option<TransportOffer> {
	let budgets = MuxBudgets { client_to_server: 4096, server_to_client: 4096 };
	let offer = TransportOffer::mux(1).with_chunk_payload_size(1024).with_budgets(budgets);
	Some(offer)
}

/// The house, which invoices every session and every renewal. An unpaid or
/// short-paid invoice fails closed with [`INVOICE_REFUSAL_CODE`].
struct LotteryHouse {
	invoice: OctetString,
	expected_payment: OctetString,
}

impl LotteryHouse {
	fn open() -> Result<Self, TightBeamError> {
		Ok(Self {
			invoice: OctetString::new(LOTTERY_INVOICE)?,
			expected_payment: OctetString::new(LOTTERY_PAYMENT)?,
		})
	}
}

impl TransportAuthorizer for LotteryHouse {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let grant =
				AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(self.invoice.to_owned()) };
			Ok(grant)
		})
	}

	fn challenge_renewal<'a>(
		&'a self,
		_prior: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, AuthorizationRefusal>> {
		Box::pin(async move { Ok(Some(self.invoice.to_owned())) })
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
		_client: &'a Certificate,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if response == Some(self.expected_payment.as_bytes()) {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: INVOICE_REFUSAL_CODE })
		})
	}
}

/// A wallet that pays the first invoice, then refuses every renewal invoice
/// with [`WALLET_EMPTY_CODE`]: the gambler is out of money.
struct EmptyWallet {
	payment: OctetString,
	invoices: AtomicUsize,
}

impl EmptyWallet {
	fn with_one_payment() -> Result<Self, TightBeamError> {
		Ok(Self { payment: OctetString::new(LOTTERY_PAYMENT)?, invoices: AtomicUsize::new(0) })
	}
}

impl ReceiptApprover for EmptyWallet {
	fn approve<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		let invoice = self.invoices.fetch_add(1, Ordering::SeqCst);
		Box::pin(async move {
			if invoice == 0 {
				return Ok(Some(self.payment.to_owned()));
			}

			Err(ApprovalRefusal { code: WALLET_EMPTY_CODE })
		})
	}
}

struct PaywallContext {
	materials: ServerMaterials,
	client_certificate: Arc<Certificate>,
	client_provider: Arc<dyn SigningKeyProvider>,
}

impl PaywallContext {
	fn generate() -> Self {
		let signing_key = random_signing_key();
		let client_certificate = Arc::new(test_certificate(&signing_key));
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { materials: ServerMaterials::generate(), client_certificate, client_provider }
	}
}

/// The lottery service behind the paywall, which decodes the ticket's pick
/// and announces the rigged outcome.
async fn start_lottery_server(
	ctx: &PaywallContext,
	rig: DrawRig,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_mutual_listener(&ctx.materials, &ctx.client_certificate).await?;
	let addr = TightBeamSocketAddr(addr);
	let authorizer: Arc<dyn TransportAuthorizer> = Arc::new(LotteryHouse::open()?);
	let handle = server! {
		protocol TokioListener: listener,
		policies: {
			with_mux_offer: [ lottery_offer() ],
			with_transport_authorizer: [ Arc::clone(&authorizer) ]
		},
		handle: move |ticket: Frame| async move {
			let pick: TestMessage = decode(ticket.message())?;
			let announced = rig.outcome(&pick.content);
			Ok(Some(TestFrame::v0(Some(&announced), None)))
		}
	};

	Ok((handle, addr))
}

/// The house's account book: the unspent draw credits of each authenticated
/// client public key. The book outlives every connection, so a gambler that
/// reconnects resumes the balance that a lost connection left behind.
#[derive(Default)]
struct CreditLedger {
	accounts: Mutex<HashMap<Vec<u8>, u64>>,
}

impl CreditLedger {
	/// The house's announcement for one ticket: a rigged outcome that debits
	/// one credit while the account holds credit, and [`ACCOUNT_EMPTY`] after.
	/// The first ticket from a public key deposits the opening balance.
	fn announce(&self, account: impl AsRef<[u8]>, rig: DrawRig, pick: impl AsRef<str>) -> String {
		let account = account.as_ref();
		let pick = pick.as_ref();
		let mut accounts = self.lock();
		let balance = accounts.entry(account.to_vec()).or_insert(DRAW_CREDITS);
		match balance {
			0 => ACCOUNT_EMPTY.to_owned(),
			_ => {
				*balance -= 1;
				rig.outcome(pick)
			}
		}
	}

	fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, u64>> {
		match self.accounts.lock() {
			Ok(accounts) => accounts,
			Err(poisoned) => poisoned.into_inner(),
		}
	}
}

/// The lottery service whose credits live in a [`CreditLedger`] keyed by the
/// client's public key. The session-aware handler meters every ticket against
/// the durable account of the authenticated peer.
async fn start_ledger_lottery_server(
	ctx: &PaywallContext,
	rig: DrawRig,
	ledger: Arc<CreditLedger>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_mutual_listener(&ctx.materials, &ctx.client_certificate).await?;
	let addr = TightBeamSocketAddr(addr);
	let authorizer: Arc<dyn TransportAuthorizer> = Arc::new(LotteryHouse::open()?);
	let handle = server! {
		protocol TokioListener: listener,
		policies: {
			with_mux_offer: [ ledger_offer() ],
			with_transport_authorizer: [ Arc::clone(&authorizer) ]
		},
		handle: move |ticket: Frame, session: SessionContext| {
			let ledger = Arc::clone(&ledger);
			async move {
				let account = session
					.peer_key()
					.map(CanonicalKey::as_der)
					.ok_or_else(|| expectation_failure("mutual handshake left no client public key"))?;
				let pick: TestMessage = decode(ticket.message())?;
				let announced = ledger.announce(account, rig, &pick.content);
				Ok(Some(TestFrame::v0(Some(&announced), None)))
			}
		}
	};

	Ok((handle, addr))
}

/// Builds the pool for a gambler. `wallet` decides how the gambler pays each
/// invoice, or whether it pays at all.
fn lottery_pool(
	ctx: &PaywallContext,
	trace: &TraceCollector,
	wallet: Option<Arc<dyn ReceiptApprover>>,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	pool_with_offer(ctx, trace, wallet, lottery_offer())
}

/// Builds a pool over the generous ledger offer, with the same paywall and
/// the same meter on each account.
fn ledger_pool(
	ctx: &PaywallContext,
	trace: &TraceCollector,
	wallet: Option<Arc<dyn ReceiptApprover>>,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	pool_with_offer(ctx, trace, wallet, ledger_offer())
}

fn pool_with_offer(
	ctx: &PaywallContext,
	trace: &TraceCollector,
	wallet: Option<Arc<dyn ReceiptApprover>>,
	mux_offer: Option<TransportOffer>,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&ctx.materials.certificate)?;
	let client_certificate = ctx.client_certificate.as_ref().to_owned();
	let identity = CertificateSpec::Built(Box::new(client_certificate));
	let client_provider = Arc::clone(&ctx.client_provider);
	let config = PoolConfig { idle_timeout: None, max_connections: 1, mux_offer: mux_offer.map(Arc::new) };
	let mut builder = ConnectionPool::<TokioListener>::builder()
		.with_config(config)
		.with_trust_store(trust_store)
		.with_client_identity(SigningIdentity::from_spec(identity, client_provider)?)
		.with_trace(trace.share());

	if let Some(wallet) = wallet {
		builder = builder.with_receipt_approver(wallet);
	}

	let pool = Arc::new(builder.build());
	Ok(pool)
}

/// Plays one draw: it emits the pick as a ticket and returns the number
/// that the house announces.
async fn draw(lease: &mut PooledClient<TokioListener>, pick: impl AsRef<str>) -> Result<String, TightBeamError> {
	let pick = pick.as_ref();
	let ticket = TestFrame::v0(Some(pick), None);
	let Some(announcement) = lease.emit(ticket, None).await? else {
		return Err(expectation_failure("draw produced no announcement"));
	};

	let announced: TestMessage = decode(announcement.message())?;
	Ok(announced.content)
}

#[derive(Default)]
struct DrawTally {
	wins: u64,
	losses: u64,
	cutoff: Option<TightBeamError>,
}

/// Asserts each clause of an all-win tally on its own, so a failure names the
/// exact clause instead of one compound boolean.
fn assert_winning_tally(tally: &DrawTally, expected_wins: u64) {
	assert_eq!(tally.wins, expected_wins, "every draw must win");
	assert_eq!(tally.losses, 0, "the always-win rig must lose no draw");
	assert!(tally.cutoff.is_none(), "no draw may be cut off: {:?}", tally.cutoff);
}

/// Draws until the house cuts the gambler off or `attempts` runs out.
async fn draw_until_cutoff(lease: &mut PooledClient<TokioListener>, attempts: u64) -> DrawTally {
	let mut tally = DrawTally::default();
	for _ in 0..attempts {
		match draw(lease, LUCKY_NUMBER).await {
			Ok(announced) if announced == LUCKY_NUMBER => tally.wins += 1,
			Ok(_) => tally.losses += 1,
			Err(error) => {
				tally.cutoff = Some(error);
				break;
			}
		}
	}

	tally
}

/// Draws until the house announces an empty account or `attempts` runs
/// out, and returns the wins tallied and whether the broke announcement
/// arrived.
async fn draw_until_broke(
	lease: &mut PooledClient<TokioListener>,
	attempts: u64,
) -> Result<(u64, bool), TightBeamError> {
	let mut wins = 0;
	for _ in 0..attempts {
		let announced = draw(lease, LUCKY_NUMBER).await?;
		if announced == ACCOUNT_EMPTY {
			return Ok((wins, true));
		}
		if announced == LUCKY_NUMBER {
			wins += 1;
		}
	}

	Ok((wins, false))
}

tb_assert_spec! {
	pub PaywallPaidDrawsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(0))
		]
	}
}

// A paid invoice opens the lottery. On the always-win rig, every announced
// number repeats the gambler's pick, well inside the prepaid credits.
tb_scenario! {
	name: paywall_paid_invoice_unlocks_winning_draws,
	spec: PaywallPaidDrawsSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move { start_lottery_server(&env.context, DrawRig::AlwaysWin).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(PayingApprover::answering(LOTTERY_PAYMENT)?);
			let pool = lottery_pool(&ctx, &trace, Some(wallet))?;
			let mut lease = pool.connect(addr).await?;

			let tally = draw_until_cutoff(&mut lease, prepaid_draws() - 1).await;
			assert_winning_tally(&tally, prepaid_draws() - 1);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallUnpaidLockoutSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(SETTLEMENT_UNSUPPORTED_CODE))
		]
	}
}

// A client without a receipt approver cannot countersign the invoice, so
// the handshake fails closed before any draw.
tb_scenario! {
	name: paywall_unpaid_invoice_locks_service,
	spec: PaywallUnpaidLockoutSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move { start_lottery_server(&env.context, DrawRig::AlwaysWin).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = lottery_pool(&ctx, &trace, None)?;
			let locked_out = pool.connect(addr).await.is_err();
			assert!(locked_out, "a client without an approver must be locked out");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallExhaustedCreditsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(WALLET_EMPTY_CODE)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::POOL_EVICTED, exactly!(1))
		]
	}
}

// On the house rig every draw loses, and the gambler's wallet refuses the
// top-up invoice: the prepaid credits buy the exact draw count, and the
// refused renewal then drains the window shut.
tb_scenario! {
	name: paywall_house_rig_exhausts_draw_credits,
	spec: PaywallExhaustedCreditsSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move { start_lottery_server(&env.context, DrawRig::HouseAlwaysWins).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(EmptyWallet::with_one_payment()?);
			let pool = lottery_pool(&ctx, &trace, Some(wallet))?;
			let mut lease = pool.connect(addr).await?;

			let tally = draw_until_cutoff(&mut lease, prepaid_draws()).await;
			assert_eq!(tally.wins, 0, "the house rig must never pay");
			assert_eq!(tally.losses, prepaid_draws(), "every prepaid draw must be served and lost");

			// The last prepaid draw opens the refused top-up renewal. The wait
			// ends on the GoAway that follows, so the next ticket always meets
			// a drained window.
			let drained = await_transport(|| trace.recorded(events::MUX_GOAWAY_SENT) > 0).await;
			assert!(drained, "the refused renewal must drain the window with a GoAway");

			// Stimulus for `events::MUX_EMIT_DRAINING`: the drained window
			// refuses one more ticket at admission.
			let late_draw = draw(&mut lease, LUCKY_NUMBER).await;
			assert!(late_draw.is_err(), "a ticket after the drain must be refused");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallTopupSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(1)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(0))
		]
	}
}

// A wallet that pays every invoice turns the budget watermark into a top-up:
// the renewal invoice settles in-band and draws continue past the prepaid
// credits under a rotated receipt.
tb_scenario! {
	name: paywall_topup_invoice_extends_draws,
	spec: PaywallTopupSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move { start_lottery_server(&env.context, DrawRig::AlwaysWin).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(PayingApprover::answering(LOTTERY_PAYMENT)?);
			let pool = lottery_pool(&ctx, &trace, Some(wallet))?;
			let mut lease = pool.connect(addr).await?;

			let tally = draw_until_cutoff(&mut lease, prepaid_draws() + 3).await;
			assert_winning_tally(&tally, prepaid_draws() + 3);

			// The renewal rotates the receipt before it records its event, so
			// the wait ends on the event.
			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) > 0).await;
			assert!(renewed, "the paid top-up must renew the session");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallLedgerReconnectSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(events::MUX_REKEY_REQUESTED, exactly!(0))
		]
	}
}

// Credits survive a lost connection: a gambler that reconnects pays a fresh
// invoice and resumes the balance that `CreditLedger` books against its
// public key, down to the exact draw the account runs empty on.
tb_scenario! {
	name: paywall_ledger_survives_reconnect,
	spec: PaywallLedgerReconnectSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move {
			start_ledger_lottery_server(&env.context, DrawRig::AlwaysWin, Arc::new(CreditLedger::default())).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(PayingApprover::answering(LOTTERY_PAYMENT)?);

			let first_pool = ledger_pool(&ctx, &trace, Some(Arc::clone(&wallet)))?;
			let mut lease = first_pool.connect(addr).await?;

			let opening = draw_until_cutoff(&mut lease, OPENING_DRAWS).await;
			assert_winning_tally(&opening, OPENING_DRAWS);

			// The test drops the lease and the pool, which tears the transport
			// down and loses the connection while the account holds credits.
			drop(lease);
			drop(first_pool);

			let second_pool = ledger_pool(&ctx, &trace, Some(wallet))?;
			let mut lease = second_pool.connect(addr).await?;

			// The same public key reaches the same account, so exactly the
			// unspent balance remains, and the draw after it finds the
			// account empty.
			let (resumed_wins, went_broke) = draw_until_broke(&mut lease, DRAW_CREDITS).await?;
			assert_eq!(resumed_wins, DRAW_CREDITS - OPENING_DRAWS, "the reconnect must resume the unspent balance");
			assert!(went_broke, "the account must run dry after the resumed balance");
			Ok(())
		}
	}
}

/// Context for the rotated-receipt scenario: the house records the
/// distinct receipt transcript hashes its handler observes, one per
/// epoch of the session.
struct HouseBooks {
	paywall: PaywallContext,
	receipts_seen: Mutex<HashSet<Vec<u8>>>,
}

impl HouseBooks {
	fn generate() -> Self {
		Self { paywall: PaywallContext::generate(), receipts_seen: Mutex::new(HashSet::new()) }
	}

	fn note_receipt(&self, transcript: impl Into<Vec<u8>>) {
		let transcript: Vec<u8> = transcript.into();
		self.lock().insert(transcript);
	}

	fn distinct_receipts(&self) -> usize {
		self.lock().len()
	}

	fn lock(&self) -> MutexGuard<'_, HashSet<Vec<u8>>> {
		match self.receipts_seen.lock() {
			Ok(receipts) => receipts,
			Err(poisoned) => poisoned.into_inner(),
		}
	}
}

tb_assert_spec! {
	pub PaywallLiveReceiptSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(1))
		]
	}
}

// Draws past the prepaid credits arrive after the in-band renewal, so the
// handler's session context carries the epoch-1 receipt on them, and the
// house books two distinct transcript hashes across one connection.
tb_scenario! {
	name: paywall_house_observes_rotated_receipt,
	spec: PaywallLiveReceiptSpec,
	environment ServiceClient {
		context: HouseBooks::generate(),
		server: |SetupEnv { context: ctx, .. }| async move {
			let (listener, addr) = bind_mutual_listener(&ctx.paywall.materials, &ctx.paywall.client_certificate).await?;
			let addr = TightBeamSocketAddr(addr);
			let authorizer: Arc<dyn TransportAuthorizer> = Arc::new(LotteryHouse::open()?);
			let books = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_mux_offer: [ lottery_offer() ],
					with_transport_authorizer: [ Arc::clone(&authorizer) ]
				},
				handle: move |ticket: Frame, session: SessionContext| {
					let books = Arc::clone(&books);
					async move {
						let receipt = session
							.session_receipt()
							.ok_or_else(|| expectation_failure("metered session carried no receipt"))?;
						books.note_receipt(receipt.receipt().transcript_hash.to_der()?);

						let pick: TestMessage = decode(ticket.message())?;
						let announced = DrawRig::AlwaysWin.outcome(&pick.content);
						Ok(Some(TestFrame::v0(Some(&announced), None)))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(PayingApprover::answering(LOTTERY_PAYMENT)?);
			let pool = lottery_pool(&ctx.paywall, &trace, Some(wallet))?;
			let mut lease = pool.connect(addr).await?;

			// Draws past the prepaid credits force a renewal. The extra
			// tickets park until it settles and then carry epoch 1.
			let tally = draw_until_cutoff(&mut lease, prepaid_draws() + 3).await;
			assert_winning_tally(&tally, prepaid_draws() + 3);
			assert!(ctx.distinct_receipts() >= 2, "the handler must see the rotated receipt");
			Ok(())
		}
	}
}
