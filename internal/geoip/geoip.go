// Package geoip provides IP-to-country lookup using MaxMind GeoLite2 format.
package geoip

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Result holds the result of a GeoIP lookup.
type Result struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
}

// DB is a thread-safe wrapper around a MaxMind .mmdb reader.
type DB struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// Open opens an existing .mmdb file.
func Open(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("geoip: database not found: %s", path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &DB{reader: reader, path: path}, nil
}

// Lookup resolves an IP string to a country.
func (db *DB) Lookup(ipStr string) Result {
	unknown := Result{CountryCode: "XX", CountryName: "Unknown"}
	if db == nil {
		return unknown
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.reader == nil {
		return unknown
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return unknown
	}
	var rec record
	if err := db.reader.Lookup(ip, &rec); err != nil {
		return unknown
	}
	if rec.Country.ISOCode == "" {
		return unknown
	}
	name := rec.Country.Names["en"]
	if name == "" {
		name = rec.Country.ISOCode
	}
	return Result{CountryCode: rec.Country.ISOCode, CountryName: name}
}

// Close closes the underlying database reader.
func (db *DB) Close() error {
	if db == nil || db.reader == nil {
		return nil
	}
	return db.reader.Close()
}
