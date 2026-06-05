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
	opts := []passbolt.Option{}
	if viper.GetBool("insecure-skip-tls-verify") {
		opts = append(opts, passbolt.WithHTTPClient(&http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}))
	}
	return opts
}

func passboltServerURL() string {
	return strings.TrimRight(strings.TrimSpace(viper.GetString("server")), "/")
}
