// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	"decred.org/dcrwallet/v5/errors"
	"decred.org/dcrwallet/v5/wallet/walletdb"
	"github.com/decred/dcrd/blockchain/stake/v5"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

const (
	// Size of various types in bytes.
	int8Size  = 1
	int16Size = 2
	int32Size = 4
	int64Size = 8
	hashSize  = 32
)

var (
	// sstxTicket2PKHPrefix is the PkScript byte prefix for an SStx
	// P2PKH ticket output. The entire prefix is 0xba76a914, but we
	// only use the first 3 bytes.
	sstxTicket2PKHPrefix = []byte{0xba, 0x76, 0xa9}

	// sstxTicket2SHPrefix is the PkScript byte prefix for an SStx
	// P2SH ticket output.
	sstxTicket2SHPrefix = []byte{0xba, 0xa9, 0x14}
)

// Key names for various database fields.
// sstxRecords
//
//	key: sstx tx hash
//	val: sstxRecord
//
// ssgenRecords
//
//	key: sstx tx hash
//	val: serialized slice of ssgenRecords
var (
	// Bucket names.
	sstxRecordsBucketName  = []byte("sstxrecords")
	ssgenRecordsBucketName = []byte("ssgenrecords")
	ssrtxRecordsBucketName = []byte("ssrtxrecords")

	// Db related key names (main bucket).
	stakeStoreCreateDateName = []byte("stakestorecreated")
)

// deserializeSStxRecord deserializes the passed serialized tx record information.
func deserializeSStxRecord(serializedSStxRecord []byte, dbVersion uint32) (*sstxRecord, error) {
	switch {
	case dbVersion < 3:
		record := new(sstxRecord)

		curPos := 0

		// Read MsgTx size (as a uint64).
		msgTxLen := int(binary.LittleEndian.Uint64(
			serializedSStxRecord[curPos : curPos+int64Size]))
		curPos += int64Size

		// Pretend to read the pkScrLoc for the 0th output pkScript.
		curPos += int32Size

		// Read the intended voteBits and extended voteBits length (uint8).
		record.voteBitsSet = false
		voteBitsLen := int(serializedSStxRecord[curPos])
		if voteBitsLen != 0 {
			record.voteBitsSet = true
		}
		curPos += int8Size

		// Read the assumed 2 byte VoteBits as well as the extended
		// votebits (75 bytes max).
		record.voteBits = binary.LittleEndian.Uint16(
			serializedSStxRecord[curPos : curPos+int16Size])
		curPos += int16Size
		if voteBitsLen != 0 {
			record.voteBitsExt = make([]byte, voteBitsLen-int16Size)
			copy(record.voteBitsExt, serializedSStxRecord[curPos:curPos+voteBitsLen-int16Size])
		}
		curPos += stake.MaxSingleBytePushLength - int16Size

		// Prepare a buffer for the msgTx.
		buf := bytes.NewBuffer(serializedSStxRecord[curPos : curPos+msgTxLen])
		curPos += msgTxLen

		// Deserialize transaction.
		msgTx := new(wire.MsgTx)
		err := msgTx.Deserialize(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}

		// Create and save the dcrutil.Tx of the read MsgTx and set its index.
		tx := dcrutil.NewTx(msgTx)
		tx.SetIndex(dcrutil.TxIndexUnknown)
		tx.SetTree(wire.TxTreeStake)
		record.tx = tx

		// Read received unix time (int64).
		received := int64(binary.LittleEndian.Uint64(
			serializedSStxRecord[curPos : curPos+int64Size]))
		record.ts = time.Unix(received, 0)

		return record, nil

	case dbVersion >= 3:
		// Don't need to read the pkscript location, so first four bytes are
		// skipped.
		serializedSStxRecord = serializedSStxRecord[4:]

		var tx wire.MsgTx
		err := tx.Deserialize(bytes.NewReader(serializedSStxRecord))
		if err != nil {
			return nil, err
		}
		unixTime := int64(binary.LittleEndian.Uint64(serializedSStxRecord[tx.SerializeSize():]))
		return &sstxRecord{tx: dcrutil.NewTx(&tx), ts: time.Unix(unixTime, 0)}, nil

	default:
		panic("unreachable")
	}
}

// deserializeSStxTicketHash160 deserializes and returns a 20 byte script
// hash for a ticket's 0th output.
func deserializeSStxTicketHash160(serializedSStxRecord []byte) (hash160 []byte, p2sh bool, err error) {
	const pkscriptLocOffset = 0
	const txOffset = 4

	pkscriptLoc := int(binary.LittleEndian.Uint32(serializedSStxRecord[pkscriptLocOffset:])) + txOffset

	// Pop off the script prefix, then pop off the 20 bytes
	// HASH160 pubkey or script hash.
	prefixBytes := serializedSStxRecord[pkscriptLoc : pkscriptLoc+3]
	scriptHash := make([]byte, 20)
	p2sh = false
	switch {
	case bytes.Equal(prefixBytes, sstxTicket2PKHPrefix):
		scrHashLoc := pkscriptLoc + 4
		if scrHashLoc+20 >= len(serializedSStxRecord) {
			return nil, false, errors.E(errors.IO, "bad sstx record size")
		}
		copy(scriptHash, serializedSStxRecord[scrHashLoc:scrHashLoc+20])
	case bytes.Equal(prefixBytes, sstxTicket2SHPrefix):
		scrHashLoc := pkscriptLoc + 3
		if scrHashLoc+20 >= len(serializedSStxRecord) {
			return nil, false, errors.E(errors.IO, "bad sstx record size")
		}
		copy(scriptHash, serializedSStxRecord[scrHashLoc:scrHashLoc+20])
		p2sh = true
	}

	return scriptHash, p2sh, nil
}

// serializeSSTxRecord returns the serialization of the passed txrecord row.
func serializeSStxRecord(record *sstxRecord) ([]byte, error) {
		tx := record.tx.MsgTx()
		txSize := tx.SerializeSize()

		buf := make([]byte, 4+txSize+8) // pkscript location + tx + unix timestamp
		pkScrLoc := tx.PkScriptLocs()
		binary.LittleEndian.PutUint32(buf, uint32(pkScrLoc[0]))
		err := tx.Serialize(bytes.NewBuffer(buf[4:4]))
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint64(buf[4+txSize:], uint64(record.ts.Unix()))
		return buf, nil

}

// stakeStoreExists returns whether or not the stake store has already
// been created in the given database namespace.
func stakeStoreExists(ns walletdb.ReadBucket) bool {
	mainBucket := ns.NestedReadBucket(mainBucketName)
	return mainBucket != nil
}

// fetchSStxRecord retrieves a tx record from the sstx records bucket
// with the given hash.
func fetchSStxRecord(ns walletdb.ReadBucket, hash *chainhash.Hash, dbVersion uint32) (*sstxRecord, error) {
	bucket := ns.NestedReadBucket(sstxRecordsBucketName)

	key := hash[:]
	val := bucket.Get(key)
	if val == nil {
		return nil, errors.E(errors.NotExist, errors.Errorf("no ticket purchase %v", hash))
	}

	return deserializeSStxRecord(val, dbVersion)
}

// fetchSStxRecordSStxTicketHash160 retrieves a ticket 0th output script or
// pubkeyhash from the sstx records bucket with the given hash.
func fetchSStxRecordSStxTicketHash160(ns walletdb.ReadBucket, hash *chainhash.Hash) (hash160 []byte, p2sh bool, err error) {
	bucket := ns.NestedReadBucket(sstxRecordsBucketName)

	key := hash[:]
	val := bucket.Get(key)
	if val == nil {
		return nil, false, errors.E(errors.NotExist, errors.Errorf("no ticket purchase %v", hash))
	}

	return deserializeSStxTicketHash160(val)
}

// putSStxRecord inserts a given SStx record to the SStxrecords bucket.
func putSStxRecord(ns walletdb.ReadWriteBucket, record *sstxRecord) error {
	bucket := ns.NestedReadWriteBucket(sstxRecordsBucketName)

	// Write the serialized txrecord keyed by the tx hash.
	serializedSStxRecord, err := serializeSStxRecord(record)
	if err != nil {
		return errors.E(errors.IO, err)
	}
	err = bucket.Put(record.tx.Hash()[:], serializedSStxRecord)
	if err != nil {
		return errors.E(errors.IO, err)
	}
	return nil
}

// initialize creates the DB if it doesn't exist, and otherwise
// loads the database.
func initializeEmpty(ns walletdb.ReadWriteBucket) error {
	// Initialize the buckets and main db fields as needed.
	mainBucket, err := ns.CreateBucketIfNotExists(mainBucketName)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	_, err = ns.CreateBucketIfNotExists(sstxRecordsBucketName)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	_, err = ns.CreateBucketIfNotExists(ssgenRecordsBucketName)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	_, err = ns.CreateBucketIfNotExists(ssrtxRecordsBucketName)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	_, err = ns.CreateBucketIfNotExists(metaBucketName)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	createBytes := mainBucket.Get(stakeStoreCreateDateName)
	if createBytes == nil {
		createDate := uint64(time.Now().Unix())
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], createDate)
		err := mainBucket.Put(stakeStoreCreateDateName, buf[:])
		if err != nil {
			return errors.E(errors.IO, err)
		}
	}

	return nil
}
