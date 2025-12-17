use base64::{Engine as _, engine::general_purpose};
use hyper::header::{AUTHORIZATION, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;

#[derive(Clone)]
struct ProxyConfig {
    remote_host: String,
    path_prefix: String,
    auth_user: String,
    auth_pass: String,
}

impl ProxyConfig {
    fn from_env() -> Self {
        dotenvy::dotenv().ok();

        Self {
            remote_host: dotenvy::var("REMOTE_HOST")
                .unwrap_or_else(|_| "https://example.com:8443".to_string()),
            path_prefix: dotenvy::var("PATH_PREFIX").unwrap_or_else(|_| "/v1".to_string()),
            auth_user: dotenvy::var("AUTH_USER").unwrap_or_else(|_| "user".to_string()),
            auth_pass: dotenvy::var("AUTH_PASS").unwrap_or_else(|_| "password".to_string()),
        }
    }

    fn build_remote_url(&self, path: &str, query: &str) -> String {
        format!("{}{}{}{}", self.remote_host, self.path_prefix, path, query)
    }

    fn create_auth_header(&self) -> Result<HeaderValue, Box<dyn std::error::Error>> {
        let credentials = format!("{}:{}", self.auth_user, self.auth_pass);
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        let auth_value = format!("Basic {}", encoded);
        Ok(HeaderValue::from_str(&auth_value)?)
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(ProxyConfig::from_env());
    let local_addr = dotenvy::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8050".to_string());

    let addr = local_addr.parse().unwrap();

    println!("Прокси запущен на http://{}", local_addr);
    println!("Проксирует на {}{}", config.remote_host, config.path_prefix);

    let make_svc = make_service_fn(move |_conn| {
        let config = Arc::clone(&config);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let config = Arc::clone(&config);
                async move { handle_request(req, config).await }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("Ошибка сервера: {}", e);
    }
}

async fn handle_request(
    req: Request<Body>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Body>, Infallible> {
    match proxy_request(req, config).await {
        Ok(response) => Ok(response),
        Err(e) => {
            eprintln!("Ошибка прокси: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Proxy error: {}", e)))
                .unwrap())
        }
    }
}

async fn proxy_request(
    req: Request<Body>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    let method = req.method().clone();
    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Формируем новый URL с префиксом
    let remote_url = config.build_remote_url(path, &query);

    println!("{} {} -> {}", method, req.uri(), remote_url);

    // Создаём новый запрос
    let mut new_req = Request::builder().method(method).uri(remote_url);

    // Копируем заголовки (кроме Host)
    for (key, value) in req.headers().iter() {
        if key != "host" {
            new_req = new_req.header(key, value);
        }
    }

    // Добавляем Basic Authorization
    new_req = new_req.header(AUTHORIZATION, config.create_auth_header()?);

    let new_req = new_req.body(req.into_body())?;

    // Отправляем запрос
    //let https = hyper_tls::HttpsConnector::new();
    // Отправляем запрос (с поддержкой самоподписанных сертификатов)
    let mut http = hyper::client::HttpConnector::new();
    http.enforce_http(false);

    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    let https = hyper_tls::HttpsConnector::from((http, tls.into()));
    let client = Client::builder().build::<_, Body>(https);

    let response = client.request(new_req).await?;

    let status = response.status();
    println!("← Статус: {}", status);

    Ok(response)
}
