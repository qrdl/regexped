use fastedge::{
    body::Body,
    http::{Error, Request, Response, StatusCode},
};
use regex_automata::dfa::{regex::Regex, dense::Config};

static HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Regex Compiler</title>
</head>
<body>
  <h1>Regex Compiler</h1>
  <form method="POST" action="/">
    <p>
      <label>Pattern: <input type="text" name="pattern" size="40" autofocus required></label>
    </p>
    <p>
      <label>Filename: <input type="text" name="filename" value="regexp.bin" size="20"></label>
    </p>
    <p>
      <button type="submit">Compile</button>
    </p>
  </form>
</body>
</html>"#;

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            } else {
                out.push(b'%');
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_form(body: &str) -> impl Iterator<Item = (String, String)> + '_ {
    body.split('&').filter_map(|pair| {
        let mut it = pair.splitn(2, '=');
        let key = it.next()?;
        let val = it.next().unwrap_or("");
        Some((url_decode(key), url_decode(val)))
    })
}

fn compile_and_respond(pattern: &str, filename: &str) -> Result<Response<Body>, Error> {
    let re = match Regex::builder()
            .dense(Config::new().unicode_word_boundary(true))
            .build(pattern) {
        Ok(re) => re,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(Body::from(format!("Invalid regex: {}\n", e)));
        }
    };

    let (fwd_bytes, fwd_pad) = re.forward().to_bytes_native_endian();
    let (rev_bytes, rev_pad) = re.reverse().to_bytes_native_endian();

    // make single memory buffer for both forward and reverse tables, with lengths at the beginning
    let mut buf = Vec::with_capacity(
        fwd_bytes.len() + rev_bytes.len() + std::mem::size_of::<usize>() * 2,
    );
    buf.extend_from_slice(&(fwd_bytes.len() - fwd_pad).to_le_bytes());
    buf.extend_from_slice(&fwd_bytes[fwd_pad..]);
    buf.extend_from_slice(&(rev_bytes.len() - rev_pad).to_le_bytes());
    buf.extend_from_slice(&rev_bytes[rev_pad..]);

    // Sanitize filename for Content-Disposition header (strip control chars and quotes)
    let safe: String = filename
        .chars()
        .filter(|c| c.is_ascii() && *c != '"' && *c != '\\' && !c.is_ascii_control())
        .collect();
    let safe = if safe.is_empty() { "regexp.bin" } else { &safe };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", safe),
        )
        .body(Body::from(buf))
}

#[fastedge::http]
fn main(req: Request<Body>) -> Result<Response<Body>, Error> {
    let (parts, body) = req.into_parts();
    match parts.method.as_str() {
        "GET" | "HEAD" => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from(HTML)),
        "POST" => {
            let body_str = std::str::from_utf8(body.as_ref()).unwrap_or("");
            let mut pattern = String::new();
            let mut filename = String::from("regexp.bin");
            for (k, v) in parse_form(body_str) {
                if k == "pattern" {
                    pattern = v;
                } else if k == "filename" && !v.is_empty() {
                    filename = v;
                }
            }
            compile_and_respond(&pattern, &filename)
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Body::from("Method Not Allowed\n")),
    }
}
