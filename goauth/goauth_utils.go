/**
* @author mnunez
 */

package goauth

import (
	"net/http"
	"strconv"
	"strings"
)

const operatorVersionThreshold = 300000000

func IsPublic(request *http.Request) bool {
	return strings.ToLower(request.Header.Get("X-Public")) == "true"
}

func IsHandledByMiddleware(request *http.Request) bool {
	return strings.ToLower(request.Header.Get("X-Handled-By-Middleware")) == "true"
}

func GetCaller(request *http.Request) string {
	if callerId := request.Header.Get("X-Caller-Id"); callerId != "" {
		return callerId

	} else {
		return request.URL.Query().Get("caller.id")
	}
}

func GetCallerStatus(request *http.Request) string {
	if callerStatus := request.Header.Get("X-Caller-Status"); callerStatus != "" {
		return callerStatus

	} else {
		return request.URL.Query().Get("caller.status")
	}
}

func GetClientId(request *http.Request) string {
	if clientId := request.Header.Get("X-Client-Id"); clientId != "" {
		return clientId

	} else {
		return request.URL.Query().Get("client.id")
	}
}

func GetOperatorID(request *http.Request) (operatorID int, exists bool) {
	val := request.Header.Get("X-Operator-Id")
	if val == "" {
		val = request.URL.Query().Get("operator.id")
	}

	if val == "" {
		return
	}

	if id, err := strconv.Atoi(val); err == nil && id > 0 {
		return id, true
	}

	return
}

func GetRootID(request *http.Request) string {
	if rootId := request.Header.Get("X-Root-Id"); rootId != "" {
		return rootId
	} else {
		return request.URL.Query().Get("root.id")
	}
}

// IsNewOperator returns true if the operator was created via operators-api.
func IsNewOperator(request *http.Request) bool {
	id, ok := GetOperatorID(request)
	return ok && id > operatorVersionThreshold
}
