/**
* @author mnunez
 */

package apierrors

import (
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type CauseList []interface{}

type ApiError interface {
	Message() string
	Code() string
	Status() int
	Cause() CauseList
	Error() string
}

type apiErr struct {
	ErrorMessage string    `json:"message"`
	ErrorCode    string    `json:"error"`
	ErrorStatus  int       `json:"status"`
	ErrorCause   CauseList `json:"cause"`
}

func (c CauseList) ToString() string {
	return fmt.Sprint(c)
}

func (e apiErr) Code() string {
	return e.ErrorCode
}

func (e apiErr) Error() string {
	return fmt.Sprintf("Message: %s;Error Code: %s;Status: %d;Cause: %v", e.ErrorMessage, e.ErrorCode, e.ErrorStatus, e.ErrorCause)
}

func (e apiErr) Status() int {
	return e.ErrorStatus
}

func (e apiErr) Cause() CauseList {
	return e.ErrorCause
}

func (e apiErr) Message() string {
	return e.ErrorMessage
}

func NewApiError(message string, error string, status int, cause CauseList) ApiError {
	return apiErr{message, error, status, cause}
}

func NewApiErrorFromBytes(data []byte) (ApiError, error) {
	var apierr apiErr
	err := json.Unmarshal(data, &apierr)
	return apierr, err
}

func NewWrapAndTraceError(span trace.Span, apierr ApiError) ApiError {
	span.RecordError(apierr)
	span.SetStatus(codes.Error, apierr.Error())
	span.SetAttributes(
		attribute.String("error.code", apierr.Code()),
		attribute.String("error.message", apierr.Message()),
		attribute.String("error.error", apierr.Error()),
		attribute.Int("error.status", apierr.Status()),
	)
	return apierr
}
