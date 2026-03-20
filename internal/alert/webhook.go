package alert

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// WebhookSender sends alerts as JSON POST requests to a webhook URL.
type WebhookSender struct {
	url    string
	client *http.Client
}

// NewWebhookSender creates a webhook sender.
func NewWebhookSender(url string) *WebhookSender {
	return &WebhookSender{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// WebhookPayload is the JSON structure sent to the webhook.
type WebhookPayload struct {
	Source    string `json:"source"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Details  map[string]any `json:"details,omitempty"`
	Time     string `json:"timestamp"`
}

// Send delivers an alert to the webhook endpoint.
func (w *WebhookSender) Send(a Alert) error {
	payload := WebhookPayload{
		Source:   "axcerberus-waf",
		Type:     string(a.Type),
		Severity: string(a.Severity),
		Message:  a.Message,
		Details:  a.Details,
		Time:     a.Timestamp.UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cerberus-WAF/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
