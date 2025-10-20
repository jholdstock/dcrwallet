// Copyright (c) 2018-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketbuyer

import (
	"context"
	"sync"
	"testing"
	"time"

	"decred.org/dcrwallet/v5/wallet"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

type testTbWallet struct{}

func (t *testTbWallet) Unlock(ctx context.Context, passphrase []byte, timeout <-chan time.Time) error {
	return nil
}
func (t *testTbWallet) RescanPoint(ctx context.Context) (*chainhash.Hash, error) {
	return nil, nil
}
func (t *testTbWallet) BlockHeader(ctx context.Context, blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return nil, nil
}
func (t *testTbWallet) NetworkBackend() (wallet.NetworkBackend, error) {
	return nil, nil
}
func (t *testTbWallet) PurchaseTickets(ctx context.Context, n wallet.NetworkBackend, req *wallet.PurchaseTicketsRequest) (*wallet.PurchaseTicketsResponse, error) {
	return nil, nil
}
func (t *testTbWallet) NextStakeDifficultyAfterHeader(ctx context.Context, h *wire.BlockHeader) (dcrutil.Amount, error) {
	return 0, nil
}
func (t *testTbWallet) AccountBalance(ctx context.Context, account uint32, confirms int32) (wallet.Balances, error) {
	return wallet.Balances{}, nil
}
func (t *testTbWallet) MixAccount(ctx context.Context, changeAccount, mixAccount, mixBranch uint32) error {
	return nil
}

func TestTicketBuyer(t *testing.T) {
	ntfnServer := wallet.MainTipChangedNotificationsClient{
		C: make(chan *wallet.MainTipChangedNotification),
	}

	tb := New(&testTbWallet{}, chaincfg.TestNet3Params(), ntfnServer, Config{})

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tb.Run(ctx, []byte{})
	}()

	ntfnServer.C <- &wallet.MainTipChangedNotification{
		AttachedBlocks: nil,
		DetachedBlocks: nil,
		NewHeight:      0,
	}
	ntfnServer.Done()

	cancel()
	wg.Done()

}
