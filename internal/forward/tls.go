package forward

import (
	"crypto/tls"
	"net"
)

// tlsClient поднимает TLS поверх соединения с https-прокси.
// Вынесено отдельно, чтобы на этапе 4 (MITM) было куда добавить настройки.
func tlsClient(conn net.Conn, serverName string) *tls.Conn {
	return tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
}
