package proxy

import (
	"net/http"
)

// SetSecureCookie sets a secure HTTP-only cookie with consistent security settings.
func SetSecureCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureCookie(r),
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

// DeleteSecureCookie removes a cookie by setting its MaxAge to -1.
func DeleteSecureCookie(w http.ResponseWriter, r *http.Request, name string) {
	SetSecureCookie(w, r, name, "", -1)
}
