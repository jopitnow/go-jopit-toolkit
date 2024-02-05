package rest

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

var maxAge = regexp.MustCompile(`(?:max-age|s-maxage)=(\d+)`)

// Response ...
type Response struct {
	*http.Response
	Err      error
	byteBody []byte
}

// String return the Response Body as a String.
func (r *Response) String() string {
	return string(r.Bytes())
}

// Bytes return the Response Body as bytes.
func (r *Response) Bytes() []byte {
	return r.byteBody
}

// FillUp set the fill parameter with the corresponding JSON or XML response.
// fill could be `struct` or `map[string]interface{}`
func (r *Response) FillUp(fill interface{}) error {
	ctypeJSON := "application/json"
	ctypeXML := "application/xml"

	ctype := strings.ToLower(r.Header.Get("Content-Type"))

	for i := 0; i < 2; i++ {

		switch {
		case strings.Contains(ctype, ctypeJSON):
			return json.Unmarshal(r.byteBody, fill)
		case strings.Contains(ctype, ctypeXML):
			return xml.Unmarshal(r.byteBody, fill)
		case i == 0:
			ctype = http.DetectContentType(r.byteBody)
		}

	}

	return errors.New("Response format neither JSON nor XML")
}

// Debug let any request/response to be dumped, showing how the request/response
// went through the wire, only if debug mode is on on RequestBuilder.
func (r *Response) Debug() string {

	var strReq, strResp string

	if req, err := httputil.DumpRequest(r.Request, true); err != nil {
		strReq = err.Error()
	} else {
		strReq = string(req)
	}

	if resp, err := httputil.DumpResponse(r.Response, false); err != nil {
		strResp = err.Error()
	} else {
		strResp = string(resp)
	}

	const separator = "--------\n"

	dump := separator
	dump += "REQUEST\n"
	dump += separator
	dump += strReq
	dump += "\n" + separator
	dump += "RESPONSE\n"
	dump += separator
	dump += strResp
	dump += r.String() + "\n"

	return dump
}
