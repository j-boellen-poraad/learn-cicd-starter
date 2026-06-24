package auth

import (
    "net/http"
    "testing"
)

// Test case 1: No Authorization header present at all
func TestGetAPIKey_NoHeader(t *testing.T) {
    headers := http.Header{} // empty headers, nothing set

    _, err := GetAPIKey(headers) // the _ means "I don't care about the string result"

    if err == nil {
        t.Fatalf("expected an error, but got nil")
    }
    if err != ErrNoAuthHeaderIncluded {
        t.Errorf("expected ErrNoAuthHeaderIncluded, but got: %v", err)
    }
}

// Test case 2: Header exists but is malformed (wrong prefix, or missing key)
func TestGetAPIKey_MalformedHeader(t *testing.T) {
    headers := http.Header{}
    headers.Set("Authorization", "Bearer sometoken") // "Bearer" is wrong, should be "ApiKey"

    _, err := GetAPIKey(headers)

    if err == nil {
        t.Fatalf("expected an error, but got nil")
    }
    if err.Error() != "malformed authorization header" {
        t.Errorf("expected 'malformed authorization header', but got: %v", err)
    }
}

// Test case 3: Valid, correctly formatted header
func TestGetAPIKey_ValidHeader(t *testing.T) {
    headers := http.Header{}
    headers.Set("Authorization", "ApiKey mySecretKey123")

    key, err := GetAPIKey(headers)

    if err != nil {
        t.Fatalf("expected no error, but got: %v", err)
    }
    if key != "mySecretKey123" {
        t.Errorf("expected key 'mySecretKey123', but got: %v", key)
    }
}