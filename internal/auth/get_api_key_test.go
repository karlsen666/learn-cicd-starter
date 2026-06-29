package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyMissingHeader(t *testing.T) {
 testHeader := http.Header{}
 
 key, err := GetAPIKey(testHeader)

 if key != "" {
	 t.Errorf("expected empty key, got %q", key)
 }

 if err != ErrNoAuthHeaderIncluded {
	 t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
 }
}

func TestGetAPIKeyEmptyAuthorization(t *testing.T) {
 testHeader := http.Header{
	 "Authorization": []string{""},
 }
 
 key, err := GetAPIKey(testHeader)

 if key != "" {
	 t.Errorf("expected empty key, got %q", key)
 }

 if err != ErrNoAuthHeaderIncluded {
	 t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
 }
}

func TestGetAPIKeySplitError(t *testing.T) {
 testHeader := http.Header{
	 "Authorization": []string{"Malformed Key ApiKey  MyAPIK3y"},
 }

 key, err := GetAPIKey(testHeader)

 if key != "" {
	 t.Errorf("expected empty key, got %q", key)
 }

 if err == nil {
	 t.Errorf("expected error, got nil")
 }


 if err.Error() != "malformed authorization header"  {
	 t.Errorf("expected malformed authorization header, got %q", err.Error())
 } 

}

func TestGetAPIKey(t *testing.T) {
 testHeader := http.Header{
	 "Authorization": []string{"ApiKey MyAPIK3y"},
 }
 
 key, err := GetAPIKey(testHeader)

 if key == "" {
	 t.Errorf("expected MyAPIK3y APIKey, got %q", key)
 }
 if err != nil {
	 t.Errorf("expected error to be nil, got %v", err)
 }

}
