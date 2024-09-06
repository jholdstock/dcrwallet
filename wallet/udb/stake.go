// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"sync"
	"time"

	"decred.org/dcrwallet/v5/errors"
	"decred.org/dcrwallet/v5/wallet/walletdb"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

// sstxRecord is the structure for a stored SStx.
type sstxRecord struct {
	tx          *dcrutil.Tx
	ts          time.Time
	voteBitsSet bool   // Removed in version 3
	voteBits    uint16 // Removed in version 3
	voteBitsExt []byte // Removed in version 3
}

// StakeStore represents a safely accessible database of
// stake transactions.
type StakeStore struct {
	Params  *chaincfg.Params
	Manager *Manager

	ownedSStxs map[chainhash.Hash]struct{}
	mtx        sync.RWMutex // only protects ownedSStxs
}

// checkHashInStore checks if a hash exists in ownedSStxs.
func (s *StakeStore) checkHashInStore(hash *chainhash.Hash) bool {
	_, exists := s.ownedSStxs[*hash]
	return exists
}

// OwnTicket returns whether the ticket is tracked by the stake manager.
func (s *StakeStore) OwnTicket(hash *chainhash.Hash) bool {
	s.mtx.RLock()
	owned := s.checkHashInStore(hash)
	s.mtx.RUnlock()
	return owned
}

// dumpSStxHashes dumps the hashes of all owned SStxs. Note
// that this doesn't use the DB.
func (s *StakeStore) dumpSStxHashes() []chainhash.Hash {
	// Copy the hash list of sstxs. You could pass the pointer
	// directly but you risk that the size of the internal
	// ownedSStxs is later modified while the end user is
	// working with the returned list.
	ownedSStxs := make([]chainhash.Hash, len(s.ownedSStxs))

	itr := 0
	for hash := range s.ownedSStxs {
		ownedSStxs[itr] = hash
		itr++
	}

	return ownedSStxs
}

// DumpSStxHashes returns the hashes of all wallet ticket purchase transactions.
func (s *StakeStore) DumpSStxHashes() []chainhash.Hash {
	defer s.mtx.RUnlock()
	s.mtx.RLock()

	return s.dumpSStxHashes()
}

// sstxAddress returns the address for a given ticket.
func (s *StakeStore) sstxAddress(ns walletdb.ReadBucket, hash *chainhash.Hash) (stdaddr.Address, error) {
	// Access the database and store the result locally.
	thisHash160, p2sh, err := fetchSStxRecordSStxTicketHash160(ns, hash)
	if err != nil {
		return nil, err
	}
	var addr stdaddr.Address
	if p2sh {
		addr, err = stdaddr.NewAddressScriptHashV0FromHash(thisHash160, s.Params)
	} else {
		addr, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(thisHash160, s.Params)
	}
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// SStxAddress is the exported, concurrency safe version of sstxAddress.
func (s *StakeStore) SStxAddress(ns walletdb.ReadBucket, hash *chainhash.Hash) (stdaddr.Address, error) {
	return s.sstxAddress(ns, hash)
}

// TicketPurchase returns the ticket purchase transaction recorded in the "stake
// manager" portion of the DB.
//
// TODO: This is redundant and should be looked up in from the transaction
// manager.  Left for now for compatibility.
func (s *StakeStore) TicketPurchase(dbtx walletdb.ReadTx, hash *chainhash.Hash) (*wire.MsgTx, error) {
	ns := dbtx.ReadBucket(wstakemgrBucketKey)

	ticketRecord, err := fetchSStxRecord(ns, hash, DBVersion)
	if err != nil {
		return nil, err
	}
	return ticketRecord.tx.MsgTx(), nil
}

// loadManager returns a new stake manager that results from loading it from
// the passed opened database.  The public passphrase is required to decrypt the
// public keys.
func (s *StakeStore) loadOwnedSStxs(ns walletdb.ReadBucket) error {
	// Regenerate the list of tickets.
	// Perform all database lookups in a read-only view.
	ticketList := make(map[chainhash.Hash]struct{})

	// Open the sstx records database.
	bucket := ns.NestedReadBucket(sstxRecordsBucketName)

	// Store each key sequentially.
	err := bucket.ForEach(func(k []byte, v []byte) error {
		var errNewHash error
		var hash *chainhash.Hash

		hash, errNewHash = chainhash.NewHash(k)
		if errNewHash != nil {
			return errNewHash
		}
		ticketList[*hash] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}

	s.ownedSStxs = ticketList
	return nil
}

// newStakeStore initializes a new stake store with the given parameters.
func newStakeStore(params *chaincfg.Params, manager *Manager) *StakeStore {
	return &StakeStore{
		Params:     params,
		Manager:    manager,
		ownedSStxs: make(map[chainhash.Hash]struct{}),
	}
}

// openStakeStore loads an existing stake manager from the given namespace,
// waddrmgr, and network parameters.
//
// A NotExist error is returned returned when the stake store is not written to
// the db.
func openStakeStore(ns walletdb.ReadBucket, manager *Manager, params *chaincfg.Params) (*StakeStore, error) {
	// Return an error if the manager has NOT already been created in the
	// given database namespace.
	if !stakeStoreExists(ns) {
		return nil, errors.E(errors.NotExist, "no stake store")
	}

	ss := newStakeStore(params, manager)

	err := ss.loadOwnedSStxs(ns)
	if err != nil {
		return nil, err
	}

	return ss, nil
}
