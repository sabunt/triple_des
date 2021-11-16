package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDesEncrypt(t *testing.T) {
	key := []byte("123456789012345678901234")
	origText := []byte("VASIA MOSHN1200499491232133")

	eryText, err := tripleDesECBEncrypt(origText, key)
	if err != nil {
		t.Fatal(err)
	}

	desText, err2 := tripleDesECBDecrypt([]byte(eryText), key)
	if err2 != nil {
		t.Fatal(err2)
	}
	// fmt.Println(string(origText) == string(desText))

	assert.Equal(t, string(origText), string(desText))
}
