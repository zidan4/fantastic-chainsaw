use axum::{
	body::Bytes,
	extract::State,
	http::{HeaderMap, StatusCode},
	routing::{get, post},
	Json, Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
	collections::HashMap,
	env,
	error::Error,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
	stripe_secret: String,
	webhook_secret: String,
	http: reqwest::Client,
	orders: Arc<RwLock<HashMap<String, Order>>>,
}

#[derive(Clone, Serialize)]
struct Product {
	id: &'static str,
	name: &'static str,
	currency: &'static str,
	unit_amount: u64,
}

#[derive(Clone)]
struct Order {
	product_id: String,
	quantity: u32,
	status: OrderStatus,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum OrderStatus {
	Pending,
	Paid,
}

#[derive(Deserialize)]
struct CheckoutRequest {
	product_id: String,
	quantity: u32,
	email: String,
}

#[derive(Serialize)]
struct CheckoutResponse {
	order_id: String,
	checkout_url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
	error: String,
}

#[derive(Deserialize)]
struct StripeCheckoutResponse {
	url: Option<String>,
}

#[derive(Deserialize)]
struct StripeEvent {
	#[serde(rename = "type")]
	event_type: String,
	data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
	object: StripeCheckoutObject,
}

#[derive(Deserialize)]
struct StripeCheckoutObject {
	#[serde(default)]
	metadata: HashMap<String, String>,
	#[serde(default)]
	payment_status: String,
}

const PRODUCTS: &[Product] = &[
	Product {
		id: "starter-shirt",
		name: "Starter shirt",
		currency: "usd",
		unit_amount: 2500,
	},
	Product {
		id: "canvas-tote",
		name: "Canvas tote",
		currency: "usd",
		unit_amount: 1800,
	},
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
	let state = AppState {
		stripe_secret: env::var("STRIPE_SECRET_KEY")?,
		webhook_secret: env::var("STRIPE_WEBHOOK_SECRET")?,
		http: reqwest::Client::new(),
		orders: Arc::new(RwLock::new(HashMap::new())),
	};

	let app = Router::new()
		.route("/products", get(list_products))
		.route("/checkout", post(create_checkout))
		.route("/webhooks/stripe", post(stripe_webhook))
		.with_state(state);

	let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
	axum::serve(listener, app).await?;
	Ok(())
}

async fn list_products() -> Json<&'static [Product]> {
	Json(PRODUCTS)
}

async fn create_checkout(
	State(state): State<AppState>,
	Json(request): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, (StatusCode, Json<ErrorResponse>)> {
	if !(1..=10).contains(&request.quantity) || !request.email.contains('@') {
		return Err(api_error(
			StatusCode::BAD_REQUEST,
			"Provide a valid email and a quantity from 1 to 10.",
		));
	}

	let Some(product) = PRODUCTS.iter().find(|p| p.id == request.product_id) else {
		return Err(api_error(StatusCode::NOT_FOUND, "Product not found."));
	};
	let order_id = Uuid::new_v4().to_string();
	let form = vec![
		("mode".to_owned(), "payment".to_owned()),
		("customer_email".to_owned(), request.email),
		("success_url".to_owned(), "http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}".to_owned()),
		("cancel_url".to_owned(), "http://localhost:3000/cancel".to_owned()),
		("line_items[0][price_data][currency]".to_owned(), product.currency.to_owned()),
		("line_items[0][price_data][unit_amount]".to_owned(), product.unit_amount.to_string()),
		("line_items[0][price_data][product_data][name]".to_owned(), product.name.to_owned()),
		("line_items[0][quantity]".to_owned(), request.quantity.to_string()),
		("metadata[order_id]".to_owned(), order_id.clone()),
	];

	let response = state
		.http
		.post("https://api.stripe.com/v1/checkout/sessions")
		.basic_auth(&state.stripe_secret, Some(""))
		.form(&form)
		.send()
		.await
		.map_err(|_| api_error(StatusCode::BAD_GATEWAY, "Payment provider unavailable."))?;

	if !response.status().is_success() {
		return Err(api_error(StatusCode::BAD_GATEWAY, "Could not create checkout session."));
	}
	let session: StripeCheckoutResponse = response
		.json()
		.await
		.map_err(|_| api_error(StatusCode::BAD_GATEWAY, "Invalid payment provider response."))?;
	let checkout_url = session
		.url
		.ok_or_else(|| api_error(StatusCode::BAD_GATEWAY, "Checkout URL missing."))?;

	state.orders.write().await.insert(
		order_id.clone(),
		Order {
			product_id: product.id.to_owned(),
			quantity: request.quantity,
			status: OrderStatus::Pending,
		},
	);

	Ok(Json(CheckoutResponse { order_id, checkout_url }))
}

async fn stripe_webhook(
	State(state): State<AppState>,
	headers: HeaderMap,
	body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
	let signature = headers
		.get("stripe-signature")
		.and_then(|value| value.to_str().ok())
		.ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Missing Stripe signature."))?;
	if !verify_stripe_signature(&state.webhook_secret, signature, &body) {
		return Err(api_error(StatusCode::BAD_REQUEST, "Invalid Stripe signature."));
	}

	let event: StripeEvent = serde_json::from_slice(&body)
		.map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid webhook payload."))?;
	if event.event_type == "checkout.session.completed"
		&& event.data.object.payment_status == "paid"
	{
		if let Some(order_id) = event.data.object.metadata.get("order_id") {
			if let Some(order) = state.orders.write().await.get_mut(order_id) {
				order.status = OrderStatus::Paid;
			}
		}
	}
	Ok(StatusCode::OK)
}

fn verify_stripe_signature(secret: &str, header: &str, body: &[u8]) -> bool {
	let mut timestamp = None;
	let mut signatures = Vec::new();
	for part in header.split(',') {
		if let Some(value) = part.strip_prefix("t=") {
			timestamp = value.parse::<u64>().ok();
		} else if let Some(value) = part.strip_prefix("v1=") {
			signatures.push(value);
		}
	}
	let Some(timestamp) = timestamp else { return false };
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|duration| duration.as_secs())
		.unwrap_or(0);
	if now.abs_diff(timestamp) > 300 {
		return false;
	}

	let mut signed_payload = timestamp.to_string().into_bytes();
	signed_payload.push(b'.');
	signed_payload.extend_from_slice(body);
	signatures.into_iter().any(|signature| {
		let Ok(signature) = hex::decode(signature) else { return false };
		let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else { return false };
		mac.update(&signed_payload);
		mac.verify_slice(&signature).is_ok()
	})
}

fn api_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
	(status, Json(ErrorResponse { error: message.to_owned() }))
}