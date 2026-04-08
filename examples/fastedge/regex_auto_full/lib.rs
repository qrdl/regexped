use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use regex_automata::dfa::{dense, dense::DFA, regex::Regex as DfaRegex};

const EMAIL_PATTERN: &str = r"^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$";
const URL_PATTERN: &str = r"^https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(/[^\s]*)?$";
const XSS_PATTERN: &str = r"(?i)(?:<\s*(?:script|iframe|object|embed|applet|frameset)\b[^>]*>|\bon\w{1,30}\s*=|(?:javascript|vbscript)\s*:|expression\s*\()";

fn build_regex(pattern: &str) -> Result<DfaRegex<DFA<Vec<u32>>>, String> {
    DfaRegex::builder()
        .dense(dense::Config::new().unicode_word_boundary(true))
        .build(pattern)
        .map_err(|e| e.to_string())
}

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
            self.send_http_response(INVALID_REQUEST, vec![], Some("Missing request body".as_bytes()));
            return Action::Pause;
        };

        let Ok(p) = serde_json::from_slice::<RequestParams>(&body) else {
            self.send_http_response(INVALID_REQUEST, vec![], Some("Invalid request body".as_bytes()));
            return Action::Pause;
        };

        println!("Received request: email={}, url={}, descr={}", p.email, p.url, p.descr);

        // validate the e-mail address
        let email_re = match build_regex(EMAIL_PATTERN) {
            Ok(re) => re,
            Err(e) => {
                println!("Failed to compile email regex: {}", e);
                self.send_http_response(500, vec![], Some(e.as_bytes()));
                return Action::Pause;
            }
        };
        if !email_re.is_match(p.email.as_bytes()) {
            println!("Email validation failed for: {}", p.email);
            self.send_http_response(INVALID_REQUEST, vec![], Some("Invalid email address".as_bytes()));
            return Action::Pause;
        }

        // validate the URL
        let url_re = match build_regex(URL_PATTERN) {
            Ok(re) => re,
            Err(e) => {
                println!("Failed to compile URL regex: {}", e);
                self.send_http_response(500, vec![], Some(e.as_bytes()));
                return Action::Pause;
            }
        };
        if !url_re.is_match(p.url.as_bytes()) {
            println!("URL validation failed for: {}", p.url);
            self.send_http_response(INVALID_REQUEST, vec![], Some("Invalid URL".as_bytes()));
            return Action::Pause;
        }

        // check for XSS in description
        let xss_re = match build_regex(XSS_PATTERN) {
            Ok(re) => re,
            Err(e) => {
                println!("Failed to compile XSS regex: {}", e);
                self.send_http_response(500, vec![], Some(e.as_bytes()));
                return Action::Pause;
            }
        };
        if xss_re.is_match(p.descr.as_bytes()) {
            println!("XSS detected in description: {}", p.descr);
            self.send_http_response(INVALID_REQUEST, vec![], Some("XSS detected in description".as_bytes()));
            return Action::Pause;
        }

        print!("Request passed all checks, forwarding to upstream");

        Action::Continue // checks passed
    }
}
