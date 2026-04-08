use proxy_wasm::traits::*;
use proxy_wasm::types::*;

#[derive(serde::Deserialize)]
struct RequestParams {
    email: String,
    url: String,
    descr: String,
}

const INVALID_REQUEST: u32 = 400;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpHeadersRoot) });
}}

struct HttpHeadersRoot;

impl Context for HttpHeadersRoot {}

impl RootContext for HttpHeadersRoot {
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpReqBody {}))
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct HttpReqBody {}

impl Context for HttpReqBody {}

impl HttpContext for HttpReqBody {
    fn on_http_request_body(&mut self, size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            return Action::Pause;
        }

        match self.get_property(vec!["request.method"]) {
            Some(method) if method == b"POST" => (),
            _ => {
                self.send_http_response(INVALID_REQUEST, vec![], Some("Invalid request method".as_bytes()));
                return Action::Pause;
            }
        }

        match self.get_http_request_header("Content-Type") {
            Some(content_type) if content_type == "application/json" => (),
            _ => {
                self.send_http_response(INVALID_REQUEST, vec![], Some("Unsupported Content-Type".as_bytes()));
                return Action::Pause;
            }
        }

        let Some(body) = self.get_http_request_body(0, size) else {
            // no body - error
            self.send_http_response(INVALID_REQUEST, vec![], Some("Missing request body".as_bytes()));
            return Action::Pause;
        };

        let Ok(p) = serde_json::from_slice::<RequestParams>(&body) else {
            // malformed body
            self.send_http_response(INVALID_REQUEST, vec![], Some("Invalid request body".as_bytes()));
            return Action::Pause;
        };

        println!("Received request: email={}, url={}, descr={}", p.email, p.url, p.descr);

        Action::Continue // checks passed
    }
}
