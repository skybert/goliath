package iam

import (
	"log"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var k = koanf.New(".")

type GoliathConf interface {
	String(key string) string
}
type KoanfConf struct {
}

func (kc KoanfConf) String(key string) string {
	return k.String(key)
}

func NewGoliathConf() GoliathConf {
	if err := k.Load(file.Provider("conf/goliath.toml"), toml.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	return KoanfConf{}
}
