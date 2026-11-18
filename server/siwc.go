package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"time"
)

func (s *Server) siwcStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"accounts": s.siwc.Status(), "connected": s.siwc.Connected(), "cyber_program": s.siwc.CyberProgram()})
}

func (s *Server) siwcDaybreak(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CyberProgram string `json:"cyber_program"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	if err := s.siwc.SetCyberProgram(body.CyberProgram); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	s.siwcStatus(w, r)
}

func (s *Server) siwcStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID string `json:"client_id"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	callback := "http://127.0.0.1:8787/api/auth/siwc/callback"
	authorize, err := s.siwc.Start(callback, body.ClientID)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"authorize_url": authorize})
}

func (s *Server) siwcCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := s.siwc.Finish(ctx, r.URL.Query())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "<!doctype html><title>ChatGPT sign-in failed</title><h1>ChatGPT sign-in failed</h1><p>%s</p><p>Return to ARTEX and try again.</p>", html.EscapeString(err.Error()))
		return
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	if !s.siwc.Connected() {
		_, _ = w.Write([]byte("<!doctype html><title>ChatGPT connected</title><h1>ChatGPT signed in</h1><p>ChatGPT plan access was not granted. Return to ARTEX and choose Continue with ChatGPT to authorize plan usage.</p>"))
		return
	}
	_, _ = w.Write([]byte("<!doctype html><title>ChatGPT connected</title><h1>ChatGPT connected to ARTEX</h1><p>You can close this tab and return to ARTEX.</p>"))
}

func (s *Server) siwcSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	if err := s.siwc.Select(body.ClientID); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	s.siwcStatus(w, r)
}

func (s *Server) siwcSignOut(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := s.siwc.SignOut(ctx)
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	writeJSON(w, 200, map[string]any{"connected": false, "revocation_confirmed": err == nil})
}
