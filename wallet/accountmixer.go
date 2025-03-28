// Copyright (c) 2018-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
)

// AccountMixer...
type AccountMixer struct {
	wallet *Wallet

	sourceAccount     uint32
	destAccount       uint32
	destAccountBranch uint32
}

// NewAccountMixer...
func (w *Wallet) NewAccountMixer(sourceAccount uint32, destAccount uint32,
	destAccountBranch uint32) *AccountMixer {
	return &AccountMixer{
		wallet:            w,
		sourceAccount:     sourceAccount,
		destAccount:       destAccount,
		destAccountBranch: destAccountBranch,
	}
}

// Run...
func (am *AccountMixer) Run(ctx context.Context, passphrase []byte) error {
	if len(passphrase) > 0 {
		err := am.wallet.Unlock(ctx, passphrase, nil)
		if err != nil {
			return err
		}
	}

	c := am.wallet.NtfnServer.MainTipChangedNotifications()
	defer c.Done()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case n := <-c.C:
			if len(n.AttachedBlocks) == 0 {
				continue
			}

			// Don't perform any actions while transactions are not synced through
			// the tip block.
			rp, err := am.wallet.RescanPoint(ctx)
			if err != nil {
				log.Debugf("Skipping autobuyer actions: RescanPoint err: %v", err)
				continue
			}
			if rp != nil {
				log.Debugf("Skipping autobuyer actions: transactions are not synced")
				continue
			}

			err = am.wallet.MixAccount(ctx, am.sourceAccount, am.destAccount, am.destAccountBranch)
			if err != nil {
				log.Error(err)
			}
		}
	}
}
