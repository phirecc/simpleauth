package simpleauth

import (
	"net/http"
	"strings"
	"bytes"
	"encoding/base64"
)

type Handler struct {
	Orig http.Handler
	AuthFunc func(string, string, *http.Request) bool
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		h.requestAuth(w, r)
		return
	}

	h.Orig.ServeHTTP(w, r)
}

func (h Handler) authenticate(r *http.Request) bool {
	const basicScheme string = "Basic "

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, basicScheme) {
		return false
	}

	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return false
	}

	creds := bytes.SplitN(str, []byte(":"), 2)

	if len(creds) != 2 {
		return false
	}

	user := string(creds[0])
	pass := string(creds[1])

	return h.AuthFunc(user, pass, r)
}

func (h Handler) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
	w.WriteHeader(http.StatusUnauthorized)
}
