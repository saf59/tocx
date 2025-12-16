use base64::{Engine as _, engine::general_purpose};
use hyper::header::{AUTHORIZATION, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode};
use std::convert::Infallible;

// Конфигурация прокси
//const REQUEST_TIMEOUT_SEC: u64 = 90;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let local_addr = dotenvy::var("LOCAL_ADDR").unwrap_or("127.0.0.1:8050".to_string());
    let remote_host = dotenvy::var("REMOTE_HOST").unwrap_or("https://example.com:8443".to_string());
    let path_prefix = dotenvy::var("PATH_PREFIX").unwrap_or("/v1".to_string());
    let auth_user = dotenvy::var("AUTH_USER").unwrap_or("user".to_string());
    let auth_pass = dotenvy::var("AUTH_PASS").unwrap_or("password".to_string());

    let addr = local_addr.parse().unwrap();

    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Прокси запущен на http://{}", local_addr);
    println!("Проксирует на {}{}", remote_host, path_prefix);

    if let Err(e) = server.await {
        eprintln!("Ошибка сервера: {}", e);
    }
}

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match proxy_request(req).await {
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

async fn proxy_request(req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    let method = req.method().clone();
    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Формируем новый URL с префиксом
    let remote_url = format!("{}{}{}{}", remote_host, path_prefix, path, query);

    println!("{} {} -> {}", method, req.uri(), remote_url);

    // Создаём Basic Auth заголовок
    let credentials = format!("{}:{}", auth_user, auth_pass);
    let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
    let auth_value = format!("Basic {}", encoded);
    // Создаём новый запрос
    let mut new_req = Request::builder().method(method).uri(remote_url);

    // Копируем заголовки (кроме Host)
    for (key, value) in req.headers().iter() {
        if key != "host" {
            new_req = new_req.header(key, value);
        }
    }

    // Добавляем Basic Authorization
    new_req = new_req.header(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

    let new_req = new_req.body(req.into_body())?;

    // Отправляем запрос
    let https = hyper_tls::HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);

    let response = client.request(new_req).await?;
    // Отправляем запрос с таймаутом
    //let response = tokio::time::timeout(
    //    tokio::time::Duration::from_secs(REQUEST_TIMEOUT_SEC),
    //    client.request(new_req)
    //).await??;

    let status = response.status();
    println!("← Статус: {}", status);

    Ok(response)
}
