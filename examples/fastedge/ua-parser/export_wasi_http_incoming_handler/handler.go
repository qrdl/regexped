// Package export_wasi_http_incoming_handler is the app: componentize-go's
// generated export glue calls Handle once per request.
//
// GET parses the request's own User-Agent header, POST parses the body. The
// answer is JSON — see Result in ua.go.
package export_wasi_http_incoming_handler

import (
	"bytes"

	. "wit_component/wasi_http_types"
	"wit_component/wasi_io_streams"

	witTypes "go.bytecodealliance.org/pkg/wit/types"
)

// maxBody bounds a POSTed User-Agent string; real ones are a few hundred bytes.
const maxBody = 8 * 1024

func Handle(request *IncomingRequest, responseOut *ResponseOutparam) {
	var ua []byte
	switch request.Method().Tag() {
	case Method_Get:
		headers := request.Headers()
		if values := headers.Get("user-agent"); len(values) > 0 {
			ua = values[0]
		}
		headers.Drop()
	case Method_Post:
		body, status := readBody(request)
		switch status {
		case 413:
			respond(responseOut, 413, "text/plain", []byte("a User-Agent string is at most 8 KB\n"))
			return
		case 400:
			// Never parse what arrived of a body that failed to arrive whole.
			respond(responseOut, 400, "text/plain", []byte("could not read the request body\n"))
			return
		}
		ua = bytes.TrimSpace(body)
	default:
		respond(responseOut, 405, "text/plain", []byte("GET parses your User-Agent header, POST parses the body\n"))
		return
	}

	res, err := parse(ua)
	if err != nil {
		// Not "no match": the engine could not answer.
		respond(responseOut, 500, "text/plain", []byte(err.Error()+"\n"))
		return
	}
	respond(responseOut, 200, "application/json", append(res.AppendJSON(nil), '\n'))
}

// readBody reads the whole request body. Its status is 0 when it did, 413
// past maxBody, and 400 when the body could not be read — a stream that
// failed rather than closed, say a client that sent less than its
// Content-Length and hung up.
func readBody(request *IncomingRequest) ([]byte, int) {
	consumed := request.Consume()
	if consumed.IsErr() {
		return nil, 400
	}
	body := consumed.Ok()
	defer body.Drop()
	stream := body.Stream()
	if stream.IsErr() {
		return nil, 400
	}
	in := stream.Ok()
	defer in.Drop()
	var out []byte
	for {
		chunk := in.BlockingRead(maxBody)
		if chunk.IsErr() {
			if e := chunk.Err(); e.Tag() != wasi_io_streams.StreamError_Closed {
				e.LastOperationFailed().Drop()
				return nil, 400
			}
			return out, 0 // closed: the whole body has been read
		}
		if out = append(out, chunk.Ok()...); len(out) > maxBody {
			return nil, 413
		}
	}
}

// maxWrite is what one blocking-write-and-flush may carry in WASI 0.2: more
// traps the request.
const maxWrite = 4096

func respond(responseOut *ResponseOutparam, status uint16, contentType string, text []byte) {
	headers := MakeFields()
	headers.Append("content-type", []byte(contentType))
	response := MakeOutgoingResponse(headers)
	response.SetStatusCode(status)
	body := response.Body().Ok()
	ResponseOutparamSet(responseOut, witTypes.Ok[*OutgoingResponse, ErrorCode](response))
	if w := body.Write(); w.IsOk() {
		stream := w.Ok()
		for len(text) > 0 {
			n := min(len(text), maxWrite)
			if stream.BlockingWriteAndFlush(text[:n]).IsErr() {
				break // the client is gone: nothing left to tell it
			}
			text = text[n:]
		}
		stream.Drop()
	}
	OutgoingBodyFinish(body, witTypes.None[*Fields]())
}
