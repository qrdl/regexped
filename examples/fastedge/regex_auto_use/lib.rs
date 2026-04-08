use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use regex_automata::dfa::{dense::DFA, regex::Regex as DfaRegex};
use std::sync::OnceLock;

// email_regex.bin layout:
//   usize (LE) | forward DFA bytes | usize (LE) | reverse DFA bytes
#[repr(C, align(8))]
struct Aligned<const N: usize>([u8; N]);

const EMAIL_BYTES_LEN: usize = include_bytes!("email_regex.bin").len();
static EMAIL_REGEX_BYTES: Aligned<EMAIL_BYTES_LEN> = Aligned(*include_bytes!("email_regex.bin"));

const URL_BYTES_LEN: usize = include_bytes!("url_regex.bin").len();
static URL_REGEX_BYTES: Aligned<URL_BYTES_LEN> = Aligned(*include_bytes!("url_regex.bin"));

const XSS_BYTES_LEN: usize = include_bytes!("xss_regex.bin").len();
static XSS_REGEX_BYTES: Aligned<XSS_BYTES_LEN> = Aligned(*include_bytes!("xss_regex.bin"));

static EMAIL_REGEX: OnceLock<Result<DfaRegex<DFA<&'static [u32]>>, String>> = OnceLock::new();
static URL_REGEX: OnceLock<Result<DfaRegex<DFA<&'static [u32]>>, String>> = OnceLock::new();
static XSS_REGEX: OnceLock<Result<DfaRegex<DFA<&'static [u32]>>, String>> = OnceLock::new();

fn load_dfa_regex(
    bytes: &'static [u8],
    cell: &'static OnceLock<Result<DfaRegex<DFA<&'static [u32]>>, String>>,
) -> Result<&'static DfaRegex<DFA<&'static [u32]>>, &'static str> {
    cell.get_or_init(|| {
        let sz = std::mem::size_of::<usize>();
        let fwd_len = usize::from_le_bytes(
            bytes[..sz].try_into().map_err(|e: std::array::TryFromSliceError| e.to_string())?,
        );
        let fwd_bytes = &bytes[sz..sz + fwd_len];
        let (fwd, _) = DFA::from_bytes(fwd_bytes).map_err(|e| e.to_string())?;
        let offset = sz + fwd_len;
        let rev_len = usize::from_le_bytes(
            bytes[offset..offset + sz]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
        );
        let rev_bytes = &bytes[offset + sz..offset + sz + rev_len];
        let (rev, _) = DFA::from_bytes(rev_bytes).map_err(|e| e.to_string())?;
        Ok(DfaRegex::builder().build_from_dfas(fwd, rev))
    })
    .as_ref()
    .map_err(|e| e.as_str())
}

fn email_regex() -> Result<&'static DfaRegex<DFA<&'static [u32]>>, &'static str> {
    load_dfa_regex(&EMAIL_REGEX_BYTES.0, &EMAIL_REGEX)
}

fn url_regex() -> Result<&'static DfaRegex<DFA<&'static [u32]>>, &'static str> {
    load_dfa_regex(&URL_REGEX_BYTES.0, &URL_REGEX)
}

fn xss_regex() -> Result<&'static DfaRegex<DFA<&'static [u32]>>, &'static str> {
    load_dfa_regex(&XSS_REGEX_BYTES.0, &XSS_REGEX)
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

        // validate the e-mail address
        let email_re = match email_regex() {
            Ok(re) => re,
            Err(e) => {
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
        let url_re = match url_regex() {
            Ok(re) => re,
            Err(e) => {
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
        let xss_re = match xss_regex() {
            Ok(re) => re,
            Err(e) => {
                self.send_http_response(500, vec![], Some(e.as_bytes()));
                return Action::Pause;
            }
        };
        if xss_re.is_match(p.descr.as_bytes()) {
            println!("XSS detected in description: {}", p.descr);
            self.send_http_response(INVALID_REQUEST, vec![], Some("XSS detected in description".as_bytes()));
            return Action::Pause;
        }

        Action::Continue // checks passed
    }
}
