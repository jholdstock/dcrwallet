// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"bytes"
	"context"
	"testing"

	"decred.org/dcrwallet/v4/wallet/walletdb"
	"github.com/decred/dcrd/chaincfg/chainhash"
)

// Test_VSP_ChangedPubKey ensures that when a VSP pubkey changes, the record
// stored in the database is updated to the new value.
func Test_VSP_ChangedPubKey(t *testing.T) {
	ctx := context.Background()

	db, mgr, _, _, teardown, err := cloneDB(ctx, "vsp.kv")
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	// Insert a ticket.

	ticketHash, err := chainhash.NewHashFromStr("1234")
	if err != nil {
		panic(err)
	}

	ticket := &VSPTicket{
		Host:   "vspd url",
		PubKey: []byte("pubkey 1"),
	}

	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		return SetVSPTicket(dbtx, ticketHash, ticket)
	})
	if err != nil {
		t.Fatalf("unable to SetVSPTicket: %v", err)
	}

	// Ticket should have been inserted.

	var gotTicket *VSPTicket
	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		gotTicket, err = GetVSPTicket(dbtx, *ticketHash)
		return err
	})
	if err != nil {
		t.Fatalf("unable to GetVSPTicket: %v", err)
	}

	// VSP should have been inserted.

	var gotVSPHost *VSPHost
	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		gotVSPHost, err = GetVSPHost(dbtx, gotTicket.VSPHostID)
		return err
	})
	if err != nil {
		t.Fatalf("unable to GetVSPHost: %v", err)
	}

	// VSP pubkey should have been inserted.

	var gotVSPPubKey *VSPPubKey
	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		gotVSPPubKey, err = GetVSPPubKey(dbtx, gotVSPHost.Host)
		return err
	})
	if err != nil {
		t.Fatalf("unable to GetVSPPubKey: %v", err)
	}

	if !bytes.Equal(gotVSPPubKey.PubKey, ticket.PubKey) {
		t.Fatalf("vsp pubkey incorrect, expected %q, got $q: %v",
			ticket.PubKey, gotVSPPubKey.PubKey)
	}

	// Insert another ticket, same URL but different pubkey.

	anotherTicketHash, err := chainhash.NewHashFromStr("1234")
	if err != nil {
		panic(err)
	}

	anotherTicket := &VSPTicket{
		Host:   "vspd url",
		PubKey: []byte("pubkey 2"),
	}

	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		return SetVSPTicket(dbtx, anotherTicketHash, anotherTicket)
	})
	if err != nil {
		t.Fatalf("unable to SetVSPTicket: %v", err)
	}

	// Stored VSP Pubkey should be updated to new value.

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		gotVSPPubKey, err = GetVSPPubKey(dbtx, gotVSPHost.Host)
		return err
	})
	if err != nil {
		t.Fatalf("unable to GetVSPPubKey: %v", err)
	}

	if !bytes.Equal(gotVSPPubKey.PubKey, anotherTicket.PubKey) {
		t.Fatalf("vsp pubkey incorrect, expected %q, got %q",
			ticket.PubKey, gotVSPPubKey.PubKey)
	}
}
