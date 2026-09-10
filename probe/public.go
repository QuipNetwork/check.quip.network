package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type publicTargetKey struct{}

// WithPublicTargets restricts each connection to a checked public IP address.
func WithPublicTargets(ctx context.Context) context.Context {
	return context.WithValue(ctx, publicTargetKey{}, true)
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}

func dialContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	if restricted, _ := ctx.Value(publicTargetKey{}).(bool); !restricted {
		return dialer.DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses for public probe target %s", host)
	}
	for _, ip := range addresses {
		if !publicAddress(ip) {
			return nil, fmt.Errorf("probe destination is not public: %s", host)
		}
	}
	for _, ip := range addresses {
		var connection net.Conn
		connection, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
	}
	return nil, err
}
