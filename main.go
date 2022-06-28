package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type WebhookPayload struct {
	Ref string `json:"ref"`
}

type WebhookHandler struct {
	Dir string
	Ref string
}

func (h *WebhookHandler) Handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if keystring, ok := os.LookupEnv("WEBHOOK_SECRET"); ok {
		sig := req.Header.Get("X-Hub-Signature")
		if !strings.HasPrefix(sig, "sha1=") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Missing signature\n")
			return
		}
		sigmac, err := hex.DecodeString(sig[5:])
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Invalid signature\n")
			return
		}
		key := []byte(keystring)
		mac := hmac.New(sha1.New, key)
		mac.Write(body)
		if !hmac.Equal(sigmac, mac.Sum(nil)) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Bad signature\n")
			return
		}
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid JSON\n")
		return
	}
	if payload.Ref == "refs/heads/gh-pages" {
		cmdline := fmt.Sprintf("git clean -dfx; git fetch origin %s; git reset --hard FETCH_HEAD", h.Ref)
		cmd := exec.Command("/bin/sh", "-c", cmdline)
		cmd.Dir = h.Dir
		if err := cmd.Start(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Webhook failed\n")
		} else {
			fmt.Fprintf(w, "OK\n")
		}
	} else {
		fmt.Fprintf(w, "Not interested in this ref\n")
	}
}

func MakeHandler(dir, ref string) func(http.ResponseWriter, *http.Request) {
	h := &WebhookHandler{
		Dir: dir,
		Ref: ref,
	}
	return h.Handle
}

func main() {
	http.HandleFunc("/_webhook/homepage", MakeHandler("/var/www/homepage", "gh-pages"))
	http.HandleFunc("/_webhook/static", MakeHandler("/var/www/static", "master"))
	log.Fatal(http.ListenAndServe("127.0.0.2:9000", nil))
}
