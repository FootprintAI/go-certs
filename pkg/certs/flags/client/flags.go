package certsflagsclient

import (
	"flag"

	certsflags "github.com/footprintai/go-certs/pkg/certs/flags"
)

func init() {
	flag.StringVar(&certsflags.CaCertPath, "tls_root_crt", "", "credentials: ca crt file path")
	flag.StringVar(&certsflags.ClientKeyPath, "tls_client_key", "", "credentials: client key file path")
	flag.StringVar(&certsflags.ClientCrtPath, "tls_client_crt", "", "credentials: client crt file path")
}

func NewFlagLoader() certsflags.FlagLoader {
	return certsflags.NewFlagLoader()
}
