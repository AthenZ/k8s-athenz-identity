package util

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func parseEndpoint(endpoint string) (string, string, error) {
	parts := strings.SplitN(endpoint, "://", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid endpoint %s", endpoint)
	}
	if parts[0] != "unix" && parts[0] != "tcp" {
		return "", "", fmt.Errorf("invalid endpoint %s, expect tcp or unix scheme", endpoint)
	}
	return parts[0], parts[1], nil
}

// NewDialer returns a dial function for a UDS or TCP endpoint.
func NewDialer(endpoint string) (func(c context.Context) (net.Conn, error), error) {
	t, a, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	return func(c context.Context) (net.Conn, error) {
		return dialer.DialContext(c, t, a)
	}, nil
}

// NewListener returns a listener for a UDS or TCP endpoint.
func NewListener(endpoint string) (net.Listener, error) {
	t, a, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return net.Listen(t, a)
}
