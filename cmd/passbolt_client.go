package cmd

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/viper"
)

func newPassboltClient() (*passbolt.Client, error) {
	server := strings.TrimSpace(viper.GetString("server"))
	opts := passboltClientOptions()
	return passbolt.NewClient(server, opts...)
}

func passboltClientOptions() []passbolt.Option {
	return passboltClientOptionsForTLS(insecureSkipTLSVerify)
}

func passboltClientOptionsForTLS(skipTLSVerify bool) []passbolt.Option {
	opts := []passbolt.Option{}
	if skipTLSVerify {
		opts = append(opts, passbolt.WithHTTPClient(insecureSkipTLSHTTPClient()))
	}
	return opts
}

func insecureSkipTLSHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// #nosec G402 -- Only enabled by the explicit --insecure-skip-tls-verify flag and warned on stderr.
				InsecureSkipVerify: true,
			},
		},
	}
}

func passboltServerURL() string {
	return strings.TrimRight(strings.TrimSpace(viper.GetString("server")), "/")
}
