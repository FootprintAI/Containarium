package sentinel

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
)

// Fail2BanJailBans is the ban state and ignoreip exemptions for one
// fail2ban jail, as reported by GET /sentinel/fail2ban/bans.
type Fail2BanJailBans struct {
	// Jail is the fail2ban jail name, discovered live from
	// `fail2ban-client status` — never hardcoded (#1962).
	Jail string `json:"jail"`
	// Banned lists the IPs currently banned on this jail.
	Banned []string `json:"banned"`
	// IgnoreIP lists this jail's live ignoreip exemptions. Matters as
	// much as Banned: it answers "why was I bannable at all".
	IgnoreIP []string `json:"ignoreip"`
}

// Fail2BanBansResponse is the JSON body for GET /sentinel/fail2ban/bans.
type Fail2BanBansResponse struct {
	Jails []Fail2BanJailBans `json:"jails"`
}

// Fail2BanUnbanRequest is the JSON body POSTed to Fail2BanUnbanHandler.
type Fail2BanUnbanRequest struct {
	// Jail restricts the unban to one configured jail. Empty means
	// every jail this sentinel currently has configured.
	Jail string `json:"jail"`
	// IP is the bare address to unban — never a CIDR. A CIDR is
	// rejected with 400 before any fail2ban-client call: silently
	// unbanning only the network address of a prefix would look like
	// it worked but wouldn't (#1962).
	IP string `json:"ip"`
}

// Fail2BanUnbanResponse is the JSON body returned by
// Fail2BanUnbanHandler.
type Fail2BanUnbanResponse struct {
	// Unbanned is true if ip was actually banned (and is now unbanned)
	// on at least one of the targeted jails. False is success, not
	// failure — see Jails.
	Unbanned bool `json:"unbanned"`
	// Jails lists the jails ip was actually unbanned from — a subset
	// of the targeted jails, omitting any where it wasn't banned in
	// the first place.
	Jails []string `json:"jails"`
}

type fail2BanErrorBody struct {
	Error string `json:"error"`
}

// writeFail2BanJSONError writes a {"error": msg} body with status.
func writeFail2BanJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(fail2BanErrorBody{Error: msg})
}

// writeFail2BanError maps a fail2ban.go classification error to the
// right HTTP status (#1962): both errFail2BanUnavailable (fail2ban not
// installed / not running) and errFail2BanJailNotFound (a named jail
// fail2ban-client doesn't recognize) are 404 — "this sentinel cannot do
// that" — distinguishable from a 200 ban/unban result. Anything else is
// an unexpected failure (e.g. output that doesn't match fail2ban-client's
// documented format), reported as 500.
func writeFail2BanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errFail2BanJailNotFound), errors.Is(err, errFail2BanUnavailable):
		writeFail2BanJSONError(w, http.StatusNotFound, err.Error())
	default:
		writeFail2BanJSONError(w, http.StatusInternalServerError, err.Error())
	}
}

// Fail2BanBansHandler lists, for every jail fail2ban-client currently
// knows about on this sentinel, the live banned-IP list and the jail's
// live ignoreip exemptions (#1962). Jails are discovered dynamically
// via `fail2ban-client status` — never a hardcoded jail name — so this
// works whether the sentinel has a jail named sshpiperd, sshd, several,
// or (today, in practice — see PR description) none at all.
//
// Gated by the admin secret — the same authority tier as
// /sentinel/tunnel-tokens and /sentinel/byoc-routes: this reveals
// operational security posture (who is currently banned, and why
// anyone else wasn't), not something every cluster daemon's shared HMAC
// secret should unlock.
func (m *Manager) Fail2BanBansHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		runner := m.fail2ban()
		jails, err := fail2banListJails(runner)
		if err != nil {
			writeFail2BanError(w, err)
			return
		}

		resp := Fail2BanBansResponse{Jails: make([]Fail2BanJailBans, 0, len(jails))}
		for _, jail := range jails {
			banned, err := fail2banJailBanned(runner, jail)
			if err != nil {
				writeFail2BanError(w, err)
				return
			}
			ignoreip, err := fail2banJailIgnoreIP(runner, jail)
			if err != nil {
				writeFail2BanError(w, err)
				return
			}
			resp.Jails = append(resp.Jails, Fail2BanJailBans{
				Jail:     jail,
				Banned:   banned,
				IgnoreIP: ignoreip,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Fail2BanUnbanHandler unbans an IP address, either from one named jail
// (Jail set) or from every jail this sentinel currently has configured
// (Jail empty) — #1962. See Fail2BanUnbanResponse for the
// success/failure semantics: unbanning an address that isn't banned
// anywhere targeted is success with unbanned=false, not an error.
//
// Gated by the admin secret, same tier as Fail2BanBansHandler above —
// clearing a ban is a materially bigger capability than any read-only
// cluster daemon operation.
func (m *Manager) Fail2BanUnbanHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req Fail2BanUnbanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}

		// Validate BEFORE any fail2ban-client call (#1962): net.ParseIP
		// rejects CIDR notation (and anything else that isn't a bare
		// address) naturally. Silently unbanning only the network
		// address of a prefix would look like it worked but wouldn't.
		if req.IP == "" || net.ParseIP(req.IP) == nil {
			http.Error(w, `{"error":"ip must be a single valid IP address, not a CIDR or empty"}`, http.StatusBadRequest)
			return
		}

		runner := m.fail2ban()
		var targets []string
		if req.Jail != "" {
			targets = []string{req.Jail}
		} else {
			jails, err := fail2banListJails(runner)
			if err != nil {
				writeFail2BanError(w, err)
				return
			}
			targets = jails
		}

		resp := Fail2BanUnbanResponse{Jails: []string{}}
		for _, jail := range targets {
			unbanned, err := fail2banUnban(runner, jail, req.IP)
			if err != nil {
				writeFail2BanError(w, err)
				return
			}
			if unbanned {
				resp.Unbanned = true
				resp.Jails = append(resp.Jails, jail)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
