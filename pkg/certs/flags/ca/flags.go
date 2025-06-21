package certsflagsca

import (
	"flag"

	certsflags "github.com/footprintai/go-certs/pkg/certs/flags"
)

func init() {
	flag.StringVar(&certsflags.CaCertPath, "tls_ca_crt", "", "credentials: ca crt file path")
	flag.BoolVar(&certsflags.TLSInsecure, "tls_insecure", false, "credentials: insecure flag")
}
