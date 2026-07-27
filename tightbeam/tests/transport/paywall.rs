//! Paywall lottery integration tests.
//!
//! The full metered-service story on the real TCP + pool stack: a client
//! connects, the house presents an invoice (the settlement challenge bound
//! into the budget-bearing session receipt), the client countersigns to pay,
//! and only then does the lottery serve draws. Credits are draws: every
//! ticket debits one session-budget credit, so the negotiated budget is the
//! number of draws a paid invoice buys.
//!
//! The draw itself is rigged per scenario: the house decides whether the
//! reply repeats the client's pick (a win) or never does (the house keeps
//! the pot), which turns settlement, budget, renewal, and refusal mechanics
//! into observable lottery outcomes.

#![cfg(all(
	feature = "transport-ecies",
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

use tightbeam::at_least;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::decode;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::policy::SessionContext;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{create_v0_tightbeam, ClientEnv, SetupEnv, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, MuxSettings, TransportAuthorizer, TransportOffer,
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
use crate::transport::support::{await_receipt_rotation, bind_mutual_listener};

use tightbeam::instrumentation::events;
use tightbeam::utils::urn::Urn;

pub(crate) const CREDITS_BOUND_THE_DRAWS: Urn<'static> = Urn::new("test", "event:paywall/credits-bound-the-draws");
pub(crate) const CUTOFF_CLOSES_THE_WINDOW: Urn<'static> = Urn::new("test", "event:paywall/cutoff-closes-the-window");
pub(crate) const HOUSE_NEVER_PAYS: Urn<'static> = Urn::new("test", "event:paywall/house-never-pays");
pub(crate) const HOUSE_SEES_ROTATED_RECEIPT: Urn<'static> =
	Urn::new("test", "event:paywall/house-sees-rotated-receipt");
pub(crate) const GAMBLER_LOSES_EVERY_TICKET: Urn<'static> =
	Urn::new("test", "event:paywall/gambler-loses-every-ticket");
pub(crate) const LEDGER_BALANCE_EXACT: Urn<'static> = Urn::new("test", "event:paywall/ledger-balance-exact");
pub(crate) const LEDGER_RUNS_DRY: Urn<'static> = Urn::new("test", "event:paywall/ledger-runs-dry");
pub(crate) const INVOICE_SETTLES_BEFORE_SERVICE: Urn<'static> =
	Urn::new("test", "event:paywall/invoice-settles-before-service");
pub(crate) const TALLY_NO_CUTOFF: Urn<'static> = Urn::new("test", "event:paywall/tally-no-cutoff");
pub(crate) const TALLY_NO_LOSSES: Urn<'static> = Urn::new("test", "event:paywall/tally-no-losses");
pub(crate) const TALLY_WINS_MATCH: Urn<'static> = Urn::new("test", "event:paywall/tally-wins-match");
pub(crate) const TOPUP_ROTATES_RECEIPT: Urn<'static> = Urn::new("test", "event:paywall/topup-rotates-receipt");
pub(crate) const UNPAID_CLIENT_LOCKED_OUT: Urn<'static> = Urn::new("test", "event:paywall/unpaid-client-locked-out");

/// Invoice the house binds into every budget-bearing receipt.
const LOTTERY_INVOICE: &[u8] = b"lottery-invoice-one-credit-per-draw";

/// Payment preimage a paying client countersigns the invoice with.
const LOTTERY_PAYMENT: &[u8] = b"lottery-payment-preimage";

/// Application code for an unpaid or short-paid invoice.
const INVOICE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 40;

/// Application code a broke client refuses a renewal invoice with.
const WALLET_EMPTY_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 41;

/// The pick every gambler plays.
const LUCKY_NUMBER: &str = "123";

/// Client-to-server credits a paid invoice buys: with one-credit tickets,
/// exactly the number of draws.
const DRAW_CREDITS: u64 = 10;

/// The client-view settings the lottery negotiation lands on: both
/// sides offer `mux(1)` with 1 KiB chunks and the house grants the
/// requested draw budget.
fn lottery_settings() -> MuxSettings {
	let mut settings = MuxSettings::symmetric(1);
	settings.send_chunk_size = 1024;
	settings.recv_chunk_size = 1024;
	settings.send_budget = Some(DRAW_CREDITS);
	settings
}

/// Draws served against the initial invoice before the budget watermark
/// opens a renewal (top-up invoice) for the rest: the same public
/// watermark math the mux enforces, not a hand-copied reserve formula.
fn prepaid_draws() -> u64 {
	lottery_settings().usable_send_budget().unwrap_or_default()
}

/// Announcement for a draw against an empty ledger account.
const ACCOUNT_EMPTY: &str = "account-empty";

/// Draws spent on the first connection of the reconnect scenario.
const OPENING_DRAWS: u64 = 3;

/// How the house rigs each draw against the client's pick.
#[derive(Clone, Copy)]
enum DrawRig {
	/// The reply repeats the pick: the client always wins.
	AlwaysWin,
	/// The reply never repeats the pick: the house keeps the pot.
	HouseAlwaysWins,
}

impl DrawRig {
	/// The number the house announces for `pick`.
	fn outcome(self, pick: &str) -> String {
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

/// Offer for ledger-metered sessions: session budgets stay generous so
/// the durable account ledger is the only meter in play.
fn ledger_offer() -> Option<TransportOffer> {
	let budgets = MuxBudgets { client_to_server: 4096, server_to_client: 4096 };
	let offer = TransportOffer::mux(1).with_chunk_payload_size(1024).with_budgets(budgets);
	Some(offer)
}

/// Invoices every session and every renewal; an unpaid or short-paid
/// invoice fails closed with [`INVOICE_REFUSAL_CODE`].
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
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if response == Some(self.expected_payment.as_bytes()) {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: INVOICE_REFUSAL_CODE })
		})
	}
}

/// Pays the first invoice, then refuses every renewal invoice with
/// [`WALLET_EMPTY_CODE`]: the gambler is out of money.
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

/// Lottery service behind the paywall: decodes the ticket's pick and
/// announces the rigged outcome.
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
			let pick: TestMessage = decode(&ticket.message)?;
			let announced = rig.outcome(&pick.content);
			Ok(Some(create_v0_tightbeam(Some(&announced), None)))
		}
	};

	Ok((handle, addr))
}

/// The house's account book: remaining draw credits keyed by the
/// authenticated client public key. Outlives every connection, so a
/// reconnecting gambler resumes the balance a lost connection left behind.
#[derive(Default)]
struct CreditLedger {
	accounts: Mutex<HashMap<Vec<u8>, u64>>,
}

impl CreditLedger {
	/// The house's announcement for one ticket: a rigged outcome while
	/// the account holds credit (debiting one), [`ACCOUNT_EMPTY`] after.
	/// The first ticket from a public key deposits the opening balance.
	fn announce(&self, account: &[u8], rig: DrawRig, pick: &str) -> String {
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

/// Lottery service whose credits live in a [`CreditLedger`] keyed by the
/// client's public key rather than in per-session budgets: the session-aware
/// handler meters every ticket against the durable account of the
/// authenticated peer.
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
					.peer_public_key()
					.ok_or_else(|| expectation_failure("mutual handshake left no client public key"))?;
				let pick: TestMessage = decode(&ticket.message)?;
				let announced = ledger.announce(account, rig, &pick.content);
				Ok(Some(create_v0_tightbeam(Some(&announced), None)))
			}
		}
	};

	Ok((handle, addr))
}

/// Pool for a gambler; `wallet` is how (or whether) invoices get paid.
fn lottery_pool(
	ctx: &PaywallContext,
	trace: &TraceCollector,
	wallet: Option<Arc<dyn ReceiptApprover>>,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	pool_with_offer(ctx, trace, wallet, lottery_offer())
}

/// Pool over the generous ledger offer: same paywall, account metering.
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
	let config = PoolConfig { idle_timeout: None, max_connections: 1, mux_offer };
	let mut builder = ConnectionPool::<TokioListener>::builder()
		.with_config(config)
		.with_trust_store(trust_store)
		.with_client_identity(identity, client_provider)?
		.with_trace(trace.share());

	if let Some(wallet) = wallet {
		builder = builder.with_receipt_approver(wallet);
	}

	let pool = Arc::new(builder.build());
	Ok(pool)
}

/// One draw: emit the pick as a ticket, decode the announced number, and
/// report whether the gambler won.
async fn draw(lease: &mut PooledClient<TokioListener>, pick: &str) -> Result<String, TightBeamError> {
	let ticket = create_v0_tightbeam(Some(pick), None);
	let Some(announcement) = lease.emit(ticket, None).await? else {
		return Err(expectation_failure("draw produced no announcement"));
	};

	let announced: TestMessage = decode(&announcement.message)?;
	Ok(announced.content)
}

#[derive(Default)]
struct DrawTally {
	wins: u64,
	losses: u64,
	cutoff: Option<TightBeamError>,
}

/// Record each clause of an all-win tally as its own event, so a
/// failing spec names the exact clause instead of one compound boolean.
fn record_winning_tally(trace: &TraceCollector, tally: &DrawTally, expected_wins: u64) -> Result<(), TightBeamError> {
	trace.event_with(TALLY_WINS_MATCH, &[], tally.wins == expected_wins)?;
	trace.event_with(TALLY_NO_LOSSES, &[], tally.losses == 0)?;
	trace.event_with(TALLY_NO_CUTOFF, &[], tally.cutoff.is_none())?;
	Ok(())
}

/// Draw until the house cuts the gambler off or `attempts` runs out.
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

/// Draw until the house announces an empty account or `attempts` runs
/// out: wins tallied, plus whether the broke announcement arrived.
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
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, at_least!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(0)),
			(INVOICE_SETTLES_BEFORE_SERVICE, exactly!(1), equals!(true)),
			(TALLY_WINS_MATCH, exactly!(1), equals!(true)),
			(TALLY_NO_LOSSES, exactly!(1), equals!(true)),
			(TALLY_NO_CUTOFF, exactly!(1), equals!(true))
		]
	}
}

// Paid invoice unlocks the lottery; on the always-win rig every announced
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

			trace.event_with(INVOICE_SETTLES_BEFORE_SERVICE, &[], lease.session_receipt().is_some())?;

			let tally = draw_until_cutoff(&mut lease, prepaid_draws() - 1).await;
			record_winning_tally(&trace, &tally, prepaid_draws() - 1)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallUnpaidLockoutSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(UNPAID_CLIENT_LOCKED_OUT, exactly!(1), equals!(true))
		]
	}
}

// No wallet, no service: a client without a receipt approver cannot
// countersign the invoice, so the handshake fails closed before any draw.
tb_scenario! {
	name: paywall_unpaid_invoice_locks_service,
	spec: PaywallUnpaidLockoutSpec,
	environment ServiceClient {
		context: PaywallContext::generate(),
		server: |env| async move { start_lottery_server(&env.context, DrawRig::AlwaysWin).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = lottery_pool(&ctx, &trace, None)?;
			let locked_out = pool.connect(addr).await.is_err();
			trace.event_with(UNPAID_CLIENT_LOCKED_OUT, &[], locked_out)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallExhaustedCreditsSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::POOL_EVICTED, exactly!(1)),
			(INVOICE_SETTLES_BEFORE_SERVICE, exactly!(1), equals!(true)),
			(HOUSE_NEVER_PAYS, exactly!(1), equals!(true)),
			(GAMBLER_LOSES_EVERY_TICKET, exactly!(1), equals!(true)),
			(CREDITS_BOUND_THE_DRAWS, exactly!(1), equals!(true)),
			(CUTOFF_CLOSES_THE_WINDOW, exactly!(1), equals!(true))
		]
	}
}

// The house rig never announces the pick and the gambler's wallet cannot
// pay the top-up invoice: the prepaid credits are the exact draw count,
// then the refused renewal drains the window shut.
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

			trace.event_with(INVOICE_SETTLES_BEFORE_SERVICE, &[], lease.session_receipt().is_some())?;

			let tally = draw_until_cutoff(&mut lease, DRAW_CREDITS).await;
			trace.event_with(HOUSE_NEVER_PAYS, &[], tally.wins == 0)?;
			trace.event_with(GAMBLER_LOSES_EVERY_TICKET, &[], tally.losses == prepaid_draws())?;
			trace.event_with(CREDITS_BOUND_THE_DRAWS, &[], tally.cutoff.is_some())?;

			// Stimulus for `events::MUX_EMIT_DRAINING`: the window is
			// drained shut, so one more ticket is refused at admission.
			let late_draw = draw(&mut lease, LUCKY_NUMBER).await;
			trace.event_with(CUTOFF_CLOSES_THE_WINDOW, &[], late_draw.is_err())?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallTopupSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(1)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(0)),
			(INVOICE_SETTLES_BEFORE_SERVICE, exactly!(1), equals!(true)),
			(TALLY_WINS_MATCH, exactly!(1), equals!(true)),
			(TALLY_NO_LOSSES, exactly!(1), equals!(true)),
			(TALLY_NO_CUTOFF, exactly!(1), equals!(true)),
			(TOPUP_ROTATES_RECEIPT, exactly!(1), equals!(true))
		]
	}
}

// A wallet that keeps paying turns the budget watermark into a top-up:
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

			let initial = lease.session_receipt();
			trace.event_with(INVOICE_SETTLES_BEFORE_SERVICE, &[], initial.is_some())?;

			let tally = draw_until_cutoff(&mut lease, prepaid_draws() + 3).await;
			record_winning_tally(&trace, &tally, prepaid_draws() + 3)?;

			let rotated = await_receipt_rotation(|| lease.session_receipt(), initial.as_deref()).await;
			trace.event_with(TOPUP_ROTATES_RECEIPT, &[], rotated.is_some())?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PaywallLedgerReconnectSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(events::MUX_REKEY_REQUESTED, exactly!(0)),
			(INVOICE_SETTLES_BEFORE_SERVICE, exactly!(2), equals!(true)),
			(TALLY_WINS_MATCH, exactly!(1), equals!(true)),
			(TALLY_NO_LOSSES, exactly!(1), equals!(true)),
			(TALLY_NO_CUTOFF, exactly!(1), equals!(true)),
			(LEDGER_BALANCE_EXACT, exactly!(1), equals!(true)),
			(LEDGER_RUNS_DRY, exactly!(1), equals!(true))
		]
	}
}

// A lost connection does not forfeit credits: the house books credits
// against the authenticated public key, so a reconnecting gambler pays a
// fresh invoice but resumes the balance the dead connection left behind,
// down to the exact draw the account runs empty on.
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
			trace.event_with(INVOICE_SETTLES_BEFORE_SERVICE, &[], lease.session_receipt().is_some())?;

			let opening = draw_until_cutoff(&mut lease, OPENING_DRAWS).await;
			record_winning_tally(&trace, &opening, OPENING_DRAWS)?;

			// The lost connection: lease and pool drop, tearing the
			// transport down with credits still on the account.
			drop(lease);
			drop(first_pool);

			let second_pool = ledger_pool(&ctx, &trace, Some(wallet))?;
			let mut lease = second_pool.connect(addr).await?;
			trace.event_with(INVOICE_SETTLES_BEFORE_SERVICE, &[], lease.session_receipt().is_some())?;

			// Same public key, same account: exactly the unspent balance
			// remains, and the draw after it finds the account empty.
			let (resumed_wins, went_broke) = draw_until_broke(&mut lease, DRAW_CREDITS).await?;
			trace.event_with(LEDGER_BALANCE_EXACT, &[], resumed_wins == DRAW_CREDITS - OPENING_DRAWS)?;
			trace.event_with(LEDGER_RUNS_DRY, &[], went_broke)?;
			Ok(())
		}
	}
}

/// Context for the rotated-receipt scenario: the house records the
/// distinct receipt transcript hashes its handler observes, one per
/// epoch the session lived under.
struct HouseBooks {
	paywall: PaywallContext,
	receipts_seen: Mutex<HashSet<Vec<u8>>>,
}

impl HouseBooks {
	fn generate() -> Self {
		Self { paywall: PaywallContext::generate(), receipts_seen: Mutex::new(HashSet::new()) }
	}

	fn note_receipt(&self, transcript: Vec<u8>) {
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
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(1)),
			(TALLY_WINS_MATCH, exactly!(1), equals!(true)),
			(TALLY_NO_LOSSES, exactly!(1), equals!(true)),
			(TALLY_NO_CUTOFF, exactly!(1), equals!(true)),
			(HOUSE_SEES_ROTATED_RECEIPT, exactly!(1), equals!(true))
		]
	}
}

// The handler's session context carries the live receipt, not a
// handshake snapshot: draws past the prepaid credits arrive after the
// in-band renewal, so the house sees the epoch-1 receipt on them and
// books two distinct transcript hashes across one connection.
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

						let pick: TestMessage = decode(&ticket.message)?;
						let announced = DrawRig::AlwaysWin.outcome(&pick.content);
						Ok(Some(create_v0_tightbeam(Some(&announced), None)))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let wallet: Arc<dyn ReceiptApprover> = Arc::new(PayingApprover::answering(LOTTERY_PAYMENT)?);
			let pool = lottery_pool(&ctx.paywall, &trace, Some(wallet))?;
			let mut lease = pool.connect(addr).await?;

			// Draws past the prepaid credits force a renewal; the extra
			// tickets park until it settles and then carry epoch 1.
			let tally = draw_until_cutoff(&mut lease, prepaid_draws() + 3).await;
			record_winning_tally(&trace, &tally, prepaid_draws() + 3)?;

			trace.event_with(HOUSE_SEES_ROTATED_RECEIPT, &[], ctx.distinct_receipts() >= 2)?;
			Ok(())
		}
	}
}
