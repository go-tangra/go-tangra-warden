package httpapi

import (
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/cache"
	"github.com/go-tangra/go-tangra-warden/v4/internal/share"
)

// ShareDeps are the services behind the share routes.
type ShareDeps struct {
	Shares    *share.Service
	Cache     *cache.Cache // rate limit on public opens (nil = unlimited)
	OpenLimit int          // opens per minute per client address and per token
}

func shareError(err error) error {
	switch {
	case errors.Is(err, share.ErrInvalid):
		return ErrValidation
	case errors.Is(err, share.ErrRegionUnavailable):
		return &Error{http.StatusBadRequest, "region_unavailable"}
	case errors.Is(err, share.ErrMail):
		return ErrUnavailable
	}
	return domainError(err)
}

// sharePage is the public disclosure page: no material in the HTML and no
// token either (it arrives in the URL fragment, which browsers keep to
// themselves); the script (allowed by the gateway's CSP through the relayed
// nonce) reads it, drops it from the address bar, and opens the share on
// user action.
var sharePage = template.Must(template.New("share").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Shared credential</title>
<style nonce="{{.Nonce}}">
body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1f2933}
button{font:inherit;padding:.6rem 1.2rem;border-radius:.4rem;border:1px solid #1f2933;background:#fff;cursor:pointer}
dl{display:grid;grid-template-columns:auto 1fr;gap:.4rem 1rem}dt{color:#52606d}code{font-family:ui-monospace,monospace;word-break:break-all}
.hidden{display:none}.error{color:#b91c1c}
</style>
</head>
<body>
<h1>Shared credential</h1>
<p id="intro">Someone shared a credential with you. Reveal it once you are ready to store it safely; each reveal counts against the share's budget.</p>
<button id="open" type="button" data-test="share-open">Reveal</button>
<section id="result" class="hidden" aria-live="polite">
<dl><dt>Name</dt><dd id="name"></dd><dt>Username</dt><dd id="username"></dd><dt>Host</dt><dd id="host"></dd><dt>Password</dt><dd><code id="password" data-test="share-password"></code></dd><dt>Reveals left</dt><dd id="left"></dd></dl>
<p id="message" class="hidden"></p>
</section>
<p id="error" class="error hidden" data-test="share-error">This link is not valid any more.</p>
<script nonce="{{.Nonce}}">
(function(){
var token = (location.hash || '').slice(1);
var btn = document.getElementById('open');
function show(id, text){var el=document.getElementById(id);el.textContent=text;}
if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { document.getElementById('error').classList.remove('hidden'); btn.classList.add('hidden'); }
if (history.replaceState) { try { history.replaceState(null, '', location.pathname); } catch (e) {} }
btn.addEventListener('click', function(){
  btn.disabled = true;
  fetch('/api/warden/v1/share/open', {method:'POST', headers:{'Content-Type':'application/json','Accept':'application/json'}, credentials:'omit', body: JSON.stringify({token: token})})
  .then(function(r){ if(!r.ok){ throw new Error('refused'); } return r.json(); })
  .then(function(d){
    show('name', d.name); show('username', d.username || ''); show('host', d.host_url || ''); show('password', d.password); show('left', String(d.opens_left));
    if (d.message) { show('message', d.message); document.getElementById('message').classList.remove('hidden'); }
    document.getElementById('result').classList.remove('hidden'); document.getElementById('intro').classList.add('hidden'); btn.classList.add('hidden');
  })
  .catch(function(){ document.getElementById('error').classList.remove('hidden'); btn.classList.add('hidden'); });
});
})();
</script>
</body>
</html>
`))

// RegisterShares mounts the share routes (contracts §shares).
func (s *Server) RegisterShares(d ShareDeps) {
	s.MustHandle("GET", "/api/warden/v1/secrets/{id}/shares", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Shares.List(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), shareError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("POST", "/api/warden/v1/secrets/{id}/shares", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			RecipientEmail  string `json:"recipient_email"`
			Message         string `json:"message"`
			ValiditySeconds int    `json:"validity_seconds"`
			MaxOpens        int    `json:"max_opens"`
			CIDR            string `json:"cidr"`
			Region          string `json:"region"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Shares.Create(r.Context(), subj, r.PathValue("id"), share.Input{RecipientEmail: in.RecipientEmail, Message: in.Message, ValiditySeconds: in.ValiditySeconds, MaxOpens: in.MaxOpens, CIDR: in.CIDR, Region: in.Region})
		if err != nil {
			Fail(w, r, s.rt.Logger(), shareError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("POST", "/api/warden/v1/shares/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Shares.Cancel(r.Context(), subj, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), shareError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", "/warden/share", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex")
		w.WriteHeader(http.StatusOK)
		_ = sharePage.Execute(w, map[string]string{"Nonce": Nonce(r)})
	})
	s.MustHandle("POST", "/api/warden/v1/share/open", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Token string `json:"token"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		addr := ClientAddr(r)
		if d.Cache != nil && d.OpenLimit > 0 {
			key := addr
			if key == "" {
				key = share.Hash(in.Token)
			}
			if d.Cache.Limited(r.Context(), cache.RateKey("share-open", key), d.OpenLimit, time.Minute) || d.Cache.Limited(r.Context(), cache.RateKey("share-token", share.Hash(in.Token)), d.OpenLimit, time.Minute) {
				Fail(w, r, nil, ErrRateLimited)
				return
			}
		}
		out, err := d.Shares.Open(r.Context(), in.Token, addr)
		if err != nil {
			Fail(w, r, s.rt.Logger(), shareError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
}
