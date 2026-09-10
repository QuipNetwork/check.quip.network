package probe

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestPublicTargetPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.1.1", "::1", "fd00::1", "::ffff:127.0.0.1", "192.0.2.1"} {
		if publicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("private or reserved address accepted: %s", raw)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
}

func TestPublicDialRefusesPrivateDestination(t *testing.T) {
	ctx := WithPublicTargets(context.Background())
	if conn, err := dialContext(ctx, "tcp", "127.0.0.1:80", time.Second); err == nil {
		conn.Close()
		t.Fatal("private destination was dialed")
	}
}

func TestPublicHTTPRejectsRedirects(t *testing.T) {
	req, err := http.NewRequestWithContext(WithPublicTargets(context.Background()), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if httpClient(false, time.Second).CheckRedirect(req, nil) == nil {
		t.Fatal("public probe followed a redirect")
	}
}
