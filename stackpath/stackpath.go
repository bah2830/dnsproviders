package stackpath

import (
	"errors"

	"github.com/mholt/caddy/caddytls"
	"github.com/xenolf/lego/providers/dns/stackpath"
)

func init() {
	caddytls.RegisterDNSProvider("stackpath", NewDNSProvider)
}

// NewDNSProvider returns a new Stackpath DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment
// len(3): credentials[0] = client id
//         credentials[1] = client secret
//         credentials[2] = stack id
func NewDNSProvider(credentials ...string) (caddytls.ChallengeProvider, error) {
	switch len(credentials) {
	case 0:
		return stackpath.NewDNSProvider()
	default:
		return nil, errors.New("invalid credentials length")
	}
}
