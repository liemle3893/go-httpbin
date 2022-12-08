/**
 * Created by liemlhd on 05/Dec/2022
 */

package httpbin

import (
	"fmt"
	"github.com/gorilla/handlers"
	"go.opentelemetry.io/otel/trace"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"
)

// buildCommonLogLine builds a log entry for req in Apache Common Log Format.
// ts is the timestamp with which the entry should be logged.
// status and size are used to provide the response HTTP status and size.
func buildCommonLogLine(req *http.Request, url url.URL, ts time.Time, status int, size int) []byte {
	username := "-"
	if url.User != nil {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}

	uri := req.RequestURI

	// Requests using the CONNECT method over HTTP/2.0 must use
	// the authority field (aka r.Host) to identify the target.
	// Refer: https://httpwg.github.io/specs/rfc7540.html#CONNECT
	if req.ProtoMajor == 2 && req.Method == "CONNECT" {
		uri = req.Host
	}
	if uri == "" {
		uri = url.RequestURI()
	}

	buf := make([]byte, 0, 3*(len(host)+len(username)+len(req.Method)+len(uri)+len(req.Proto)+50)/2)
	buf = append(buf, []byte("host=")...)
	buf = append(buf, host...)
	buf = append(buf, []byte(" username=")...)
	buf = append(buf, username...)
	buf = append(buf, []byte(" ts=")...)
	buf = append(buf, ts.Format("02/Jan/2006:15:04:05.111 -0700")...)
	buf = append(buf, []byte(" method=")...)
	buf = append(buf, req.Method...)
	buf = append(buf, []byte(" uri=")...)
	buf = appendQuoted(buf, uri)
	buf = append(buf, []byte(" proto=")...)
	buf = append(buf, req.Proto...)
	buf = append(buf, []byte(" status=")...)
	buf = append(buf, strconv.Itoa(status)...)
	buf = append(buf, []byte(" size=")...)
	buf = append(buf, strconv.Itoa(size)...)
	return buf
}

func writeCombinedLog(writer io.Writer, params handlers.LogFormatterParams) {
	buf := buildCommonLogLine(params.Request, params.URL, params.TimeStamp, params.StatusCode, params.Size)
	buf = append(buf, []byte(" referer=")...)
	buf = appendQuoted(buf, params.Request.Referer())
	buf = append(buf, []byte(" useragent=")...)
	buf = appendQuoted(buf, params.Request.UserAgent())
	if span := trace.SpanFromContext(params.Request.Context()); span != nil {
		spanCtx := span.SpanContext()
		buf = append(buf, (` span_id=` + spanCtx.SpanID().String())...)
		buf = append(buf, (` trace_id=` + spanCtx.TraceID().String())...)
		buf = append(buf, (` sampled=` + fmt.Sprintf("%t", spanCtx.IsSampled()))...)
	}
	buf = append(buf, '\n')
	writer.Write(buf)
}

const lowerhex = "0123456789abcdef"

func appendQuoted(buf []byte, s string) []byte {
	var runeTmp [utf8.UTFMax]byte
	for width := 0; len(s) > 0; s = s[width:] {
		r := rune(s[0])
		width = 1
		if r >= utf8.RuneSelf {
			r, width = utf8.DecodeRuneInString(s)
		}
		if width == 1 && r == utf8.RuneError {
			buf = append(buf, `\x`...)
			buf = append(buf, lowerhex[s[0]>>4])
			buf = append(buf, lowerhex[s[0]&0xF])
			continue
		}
		if r == rune('"') || r == '\\' { // always backslashed
			buf = append(buf, '\\')
			buf = append(buf, byte(r))
			continue
		}
		if strconv.IsPrint(r) {
			n := utf8.EncodeRune(runeTmp[:], r)
			buf = append(buf, runeTmp[:n]...)
			continue
		}
		switch r {
		case '\a':
			buf = append(buf, `\a`...)
		case '\b':
			buf = append(buf, `\b`...)
		case '\f':
			buf = append(buf, `\f`...)
		case '\n':
			buf = append(buf, `\n`...)
		case '\r':
			buf = append(buf, `\r`...)
		case '\t':
			buf = append(buf, `\t`...)
		case '\v':
			buf = append(buf, `\v`...)
		default:
			switch {
			case r < ' ':
				buf = append(buf, `\x`...)
				buf = append(buf, lowerhex[s[0]>>4])
				buf = append(buf, lowerhex[s[0]&0xF])
			case r > utf8.MaxRune:
				r = 0xFFFD
				fallthrough
			case r < 0x10000:
				buf = append(buf, `\u`...)
				for s := 12; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r>>uint(s)&0xF])
				}
			default:
				buf = append(buf, `\U`...)
				for s := 28; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r>>uint(s)&0xF])
				}
			}
		}
	}
	return buf
}
