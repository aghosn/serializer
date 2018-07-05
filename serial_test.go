package main

import (
	"io/ioutil"
	"math/big"
	"testing"
	"unsafe"
)

var HashedData = "hashed.dat"
var ModulusLE = "modulus.dat"
var CorrectSignature = "signature.dat"
var CorrectQ1 = "q1.dat"
var CorrectQ2 = "q2.dat"
var testtokfile = "token.dat"
var testmetafile = "meta.dat"
var Correcttohash = "tohash.dat"
var CorrectMetaBeforeHash = "metabeforehash.dat"

const (
	SIGNATURE_SIZE = 384
)

func TestSigning(t *testing.T) {
	b, err := ioutil.ReadFile(HashedData)
	check(err)

	if len(b) != 32 {
		t.Errorf("Length of hash supposed to be 32, found %d", len(b))
	}

	key := getKey()
	signed, rsigned := signHashedData(key, b)

	csig, err := ioutil.ReadFile(CorrectSignature)
	check(err)
	if len(csig) != len(signed) {
		t.Errorf("Expected signature size %d, found %d", len(csig), len(signed))
	}
	if len(signed) != SIGNATURE_SIZE {
		t.Errorf("Wrong signature size %d", SIGNATURE_SIZE)
	}

	for i := range csig {
		if csig[i] != signed[i] {
			t.Error("The signature do not match.")
		}
	}

	for i := range signed {
		if signed[i] != rsigned[len(signed)-1-i] {
			t.Error("Signed and rsgined do not match")
		}
	}
}

func TestQ1Q2(t *testing.T) {
	cq1, err := ioutil.ReadFile(CorrectQ1)
	check(err)
	cq2, err := ioutil.ReadFile(CorrectQ2)
	check(err)

	signature, err := ioutil.ReadFile(CorrectSignature)
	check(err)

	modLE, err := ioutil.ReadFile(ModulusLE)
	check(err)

	if len(modLE) != SE_KEY_SIZE {
		t.Errorf("Wrong size for the modulus %d", len(modLE))
	}

	modulus := make([]byte, len(modLE))
	for i := range modulus {
		modulus[i] = modLE[SE_KEY_SIZE-1-i]
	}
	revSign := make([]byte, len(signature))
	for i := range signature {
		revSign[i] = signature[len(signature)-1-i]
	}

	var bigMod big.Int
	bigMod.SetBytes(modulus)

	var bigSig big.Int
	bigSig.SetBytes(revSign)

	pq1, pq2 := computeQ1Q2(&bigMod, &bigSig)
	if len(pq1) != len(cq1) {
		t.Error("Sizes q1 do not match.")
	}
	if len(pq2) != len(cq2) {
		t.Error("Sizes q2 do not match")
	}

	for i := range pq1 {
		if pq1[i] != cq1[i] {
			t.Errorf("Difference in Q1 at index %d, %d - %d", i, pq1[i], cq1[i])
		}
	}

	for i := range pq2 {
		if pq2[i] != cq2[i] {
			t.Errorf("Difference in Q2 at index %d, %d - %d", i, pq2[i], cq2[i])
		}
	}
}

func TestHashingSignPipe(t *testing.T) {
	dump, err := ioutil.ReadFile(CorrectMetaBeforeHash)
	check(err)

	if uintptr(len(dump)) != unsafe.Sizeof(enclave_css_t{}) {
		t.Errorf("Wrong file size for enclave_css, expected 1808, received %d", len(dump))
	}

	var css *enclave_css_t
	css = (*enclave_css_t)(unsafe.Pointer(&dump[0]))

	correct2hash, err := ioutil.ReadFile(Correcttohash)
	check(err)
	if len(correct2hash) != (headSize + bodySize) {
		t.Errorf("Wrong size of the tohash, expected %d, found %d", headSize+bodySize, len(correct2hash))
	}

	for i := 0; i < headSize; i++ {
		if dump[i] != correct2hash[i] {
			t.Error("Apparently the meta dump and the tempbuffer differ in head.")
		}
	}

	for i := headSize + keySize; i < headSize+keySize+bodySize; i++ {
		if dump[i] != correct2hash[i-keySize] {
			t.Error("Apparently the meta dump and the tempbuffer differ in body")
		}
	}

	hash := getHashedCss(css)

	chash, err := ioutil.ReadFile(HashedData)
	check(err)

	if len(chash) != 32 {
		t.Errorf("Wrong size for chash, expected 32, got %d", len(chash))
	}

	for i := range hash {
		if hash[i] != chash[i] {
			t.Errorf("Hash difference at index %d, %d-%d", i, hash[i], chash[i])
		}
	}
}

//func TestMetaToken(t *testing.T) {
//	key := getKey()
//	meta, tok := getMetaNToken(testmetafile, testtokfile, key)
//
//	tohash, err := ioutil.ReadFile(correcttohash)
//	check(err)
//
//}
