//go:build darwin

package machineid

import "testing"

func TestParseIoreg(t *testing.T) {
	out := []byte(`+-o J314sAP  <class IOPlatformExpertDevice>
    {
      "IOPlatformSerialNumber" = "XYZ"
      "IOPlatformUUID" = "1A2B3C4D-0000-1111-2222-333344445555"
    }`)
	got, err := parseIoreg(out)
	if err != nil || got != "1A2B3C4D-0000-1111-2222-333344445555" {
		t.Fatalf("parseIoreg = %q, %v", got, err)
	}
	if _, err := parseIoreg([]byte("nothing")); err == nil {
		t.Fatal("missing UUID must be an error")
	}
}
