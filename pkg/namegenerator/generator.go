package namegenerator

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Generator interface {
	Generate() (string, error)
}

type NameGenerator struct {
	random *int64
}

func (rn *NameGenerator) Generate() (string, error) {
	seed, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return "", fmt.Errorf("%v", err.Error())
	}

	randomAdjective := NAMES[seed.Int64()]
	randomNoun := LASTNAMES[seed.Int64()]
	randomName := fmt.Sprintf("%v-%v", randomAdjective, randomNoun)

	return randomName, nil
}

func NewNameGenerator(seed int64) Generator {
	nameGenerator := &NameGenerator{
		random: &seed,
	}
	return nameGenerator
}
