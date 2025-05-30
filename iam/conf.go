package iam

import (
	"log"
	"time"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var k = koanf.New(".")

type GoliathConf interface {
	// Lookup string from conf file
	String(key string) string

	// Lookup list of from conf file
	Strings(key string) []string

	// Lookup key from conf file. It is expected the value is
	// milliseconds. This method then returns a Time object with
	// this amount of milliseconds into the future.
	MillisAsTime(key string) time.Time
}
type KoanfConf struct {
}

func (kc KoanfConf) String(key string) string {
	return k.String(key)
}

func (kc KoanfConf) Strings(key string) []string {
	return k.Strings(key)
}

func (kc KoanfConf) MillisAsTime(key string) time.Time {
	ms := k.Int64(key)
	current := time.Now().UnixMilli()
	future := time.UnixMilli(current + ms)
	return future
}

func NewGoliathConf() GoliathConf {
	if err := k.Load(file.Provider("conf/goliath.toml"), toml.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	return KoanfConf{}
}

type GoliathCLIArgs struct {
	ServerPort int
	PKCE       bool
}
