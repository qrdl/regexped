// Package export_wasi_http_incoming_handler is the app: componentize-go's
// generated export glue calls Handle once per request.
//
// GET parses the request's own User-Agent header, POST parses the body. The
// answer is JSON — see Result in ua.go.
package export_wasi_http_incoming_handler

import (
	"bytes"

	. "wit_component/wasi_http_types"

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
		body, ok := readBody(request)
		if !ok {
			respond(responseOut, 413, "text/plain", []byte("a User-Agent string is at most 8 KB\n"))
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

// readBody reads the whole request body, or answers false past maxBody.
func readBody(request *IncomingRequest) ([]byte, bool) {
	consumed := request.Consume()
	if consumed.IsErr() {
		return nil, true
	}
	body := consumed.Ok()
	defer body.Drop()
	stream := body.Stream()
	if stream.IsErr() {
		return nil, true
	}
	in := stream.Ok()
	defer in.Drop()
	var out []byte
	for {
		chunk := in.BlockingRead(maxBody)
		if chunk.IsErr() { // closed: the whole body has been read
			return out, true
		}
		if out = append(out, chunk.Ok()...); len(out) > maxBody {
			return nil, false
		}
	}
}

func respond(responseOut *ResponseOutparam, status uint16, contentType string, text []byte) {
	headers := MakeFields()
	headers.Append("content-type", []byte(contentType))
	response := MakeOutgoingResponse(headers)
	response.SetStatusCode(status)
	body := response.Body().Ok()
	ResponseOutparamSet(responseOut, witTypes.Ok[*OutgoingResponse, ErrorCode](response))
	if w := body.Write(); w.IsOk() {
		stream := w.Ok()
		stream.BlockingWriteAndFlush(text)
		stream.Drop()
	}
	OutgoingBodyFinish(body, witTypes.None[*Fields]())
}
