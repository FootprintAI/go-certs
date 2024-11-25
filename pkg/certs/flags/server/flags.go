package certsflagssvr

import (
	"flag"

	certsflags "github.com/footprintai/go-certs/pkg/certs/flags"
)

func init() {
	flag.StringVar(&certsflags.CaCertPath, "tls_root_crt", "", "credentials: ca crt file path")
	flag.StringVar(&certsflags.SeverKeyPath, "tls_server_key", "", "credentials: server key file path")
	flag.StringVar(&certsflags.ServerCrtPath, "tls_server_crt", "", "credentials: server crt file path")
}

func NewFlagLoader() certsflags.FlagLoader {
	return certsflags.NewFlagLoader()
}