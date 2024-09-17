package loader

import (
	"sync"

	"decred.org/dcrwallet/v5/errors"
	"decred.org/dcrwallet/v5/internal/loggers"
	"decred.org/dcrwallet/v5/wallet"
)

var vspClients = struct {
	mu      sync.Mutex
	clients map[string]*wallet.VSPClient
}{
	clients: make(map[string]*wallet.VSPClient),
}

// VSP loads or creates a package-global instance of the VSP client for a host.
// This allows clients to be created and reused across various subsystems.
func VSP(cfg wallet.VSPClientConfig) (*wallet.VSPClient, error) {
	key := cfg.URL
	vspClients.mu.Lock()
	defer vspClients.mu.Unlock()
	client, ok := vspClients.clients[key]
	if ok {
		return client, nil
	}
	client, err := wallet.NewVSPClient(cfg, loggers.VspcLog)
	if err != nil {
		return nil, err
	}
	vspClients.clients[key] = client
	return client, nil
}

// LookupVSP returns a previously-configured VSP client, if one has been created
// and registered with the VSP function.  Otherwise, a NotExist error is
// returned.
func LookupVSP(host string) (*wallet.VSPClient, error) {
	vspClients.mu.Lock()
	defer vspClients.mu.Unlock()
	client, ok := vspClients.clients[host]
	if !ok {
		err := errors.Errorf("VSP client for %q not found", host)
		return nil, errors.E(errors.NotExist, err)
	}
	return client, nil
}

// AllVSPs returns the list of all currently registered VSPs.
func AllVSPs() map[string]*wallet.VSPClient {
	// Create a copy to avoid callers mutating the list.
	vspClients.mu.Lock()
	defer vspClients.mu.Unlock()
	res := make(map[string]*wallet.VSPClient, len(vspClients.clients))
	for host, client := range vspClients.clients {
		res[host] = client
	}
	return res
}
