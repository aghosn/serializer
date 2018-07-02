package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"unsafe"

	"github.com/golang/protobuf/proto"
)

const (
	aesm_socket  = "/var/run/aesmd/aesm.socket"
	target_meta  = "/tmp/gobdump_meta.dat"
	target_token = "/tmp/gobdump_req.dat"
)

var (
	privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)
)

type LaunchTokenRequest struct {
	MrEnclave        []byte  `protobuf:"bytes,1,req,name=mr_enclave,json=mrEnclave" json:"mr_enclave,omitempty"`
	MrSigner         []byte  `protobuf:"bytes,2,req,name=mr_signer,json=mrSigner" json:"mr_signer,omitempty"`
	SeAttributes     []byte  `protobuf:"bytes,3,req,name=se_attributes,json=seAttributes" json:"se_attributes,omitempty"`
	Timeout          *uint32 `protobuf:"varint,9,opt,name=timeout" json:"timeout,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func check(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func main() {
	b, err := ioutil.ReadFile(target_meta)
	check(err)

	dec := gob.NewDecoder(bytes.NewReader(b))

	var meta metadata_t

	err = dec.Decode(&meta)
	check(err)

	// decode token
	b, err = ioutil.ReadFile(target_token)
	check(err)

	dec = gob.NewDecoder(bytes.NewReader(b))
	var tok LaunchTokenRequest
	err = dec.Decode(&tok)
	check(err)

	// Parse the rsa key as well.
	block, _ := pem.Decode(privateKey)
	if block.Type != "RSA PRIVATE KEY" {
		panic("gosec: unable to parse the pem private key value.")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	check(err)

	// Set up the keys.
	for i := range meta.Enclave_css.Key.Exponent {
		meta.Enclave_css.Key.Exponent[i] = 0
	}

	for i := range meta.Enclave_css.Key.Modulus {
		meta.Enclave_css.Key.Modulus[i] = 0
	}

	exponentByte := make([]byte, SE_EXPONENT_SIZE)
	binary.LittleEndian.PutUint32(exponentByte, uint32(key.E))
	if exponentByte[0] != 0x03 {
		panic("Wrong conversion of exponent.")
	}
	for i := range exponentByte {
		meta.Enclave_css.Key.Exponent[i] = exponentByte[i]
	}

	modByte := key.N.Bytes()
	if len(modByte) != SE_KEY_SIZE {
		panic("Wrong size for modulus in bytes.")
	}
	for i := range modByte {
		meta.Enclave_css.Key.Modulus[i] = modByte[SE_KEY_SIZE-1-i]
	}

	// Do the signature.
	buff_size := int(unsafe.Sizeof(meta.Enclave_css.Header) + unsafe.Sizeof(meta.Enclave_css.Body))
	temp_buffer := make([]byte, buff_size)

	base := unsafe.Pointer(&(meta.Enclave_css.Header))
	for i := uintptr(0); i < unsafe.Sizeof(meta.Enclave_css.Header); i++ {
		val := (*byte)(unsafe.Pointer(uintptr(base) + i))
		temp_buffer[i] = *val
	}

	base = unsafe.Pointer(&(meta.Enclave_css.Body))
	for i := unsafe.Sizeof(meta.Enclave_css.Header); i < uintptr(buff_size); i++ {
		val := (*byte)(unsafe.Pointer(uintptr(base) + i))
		temp_buffer[i] = *val
	}

	signHB := sha256.Sum256(temp_buffer)
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, signHB[:])
	check(err)
	//fmt.Println(signed)

	//TODO in the code they seem to reverse the order of bytes here.
	for i := 0; i < len(signed); i++ {
		meta.Enclave_css.Key.Signature[i] = signed[len(signed)-1-i]
	}
	//TODO modulus is probably not set yet. Need to set it up.
	modulus := make([]byte, SE_KEY_SIZE)
	for i := range modulus {
		modulus[i] = meta.Enclave_css.Key.Modulus[SE_KEY_SIZE-1-i]
	}

	// Compute the RSA q1 and q2
	var bigMod big.Int
	bigMod.SetBytes(modulus)

	var bigSig big.Int
	bigSig.SetBytes(signed)

	ptemp1 := big.NewInt(int64(0))
	ptemp1.Mul(&bigSig, &bigSig)
	pQ1, ptemp2 := big.NewInt(int64(0)), big.NewInt(int64(0))
	pQ1.QuoRem(ptemp1, &bigMod, ptemp2)
	ptemp1.Mul(&bigSig, ptemp2)
	pQ2 := big.NewInt(int64(0))
	pQ2.QuoRem(ptemp1, &bigMod, ptemp2)

	pQ1Bytes := pQ1.Bytes()
	pQ2Bytes := pQ2.Bytes()

	if len(pQ1Bytes) != SE_KEY_SIZE || len(pQ2Bytes) != SE_KEY_SIZE {
		panic("Wrong pq sizes")
	}

	for i := 0; i < SE_KEY_SIZE; i++ {
		meta.Enclave_css.Buffer.Q1[i] = pQ1Bytes[SE_KEY_SIZE-1-i]
		meta.Enclave_css.Buffer.Q2[i] = pQ2Bytes[SE_KEY_SIZE-1-i]
	}

	//TODO not sure what the dir is supposed to be.
	//TODO not sure what the size is supposed to be either.

	timeout := uint32(1000)
	req := Request{}
	tok.MrEnclave = meta.Enclave_css.Body.Enclave_hash.M[:]
	tok.MrSigner = meta.Enclave_css.Key.Modulus[:]
	tok.Timeout = &timeout
	req.GetLicTokenReq = &Request_GetLaunchTokenRequest{tok.MrEnclave,
		tok.MrSigner, tok.SeAttributes, tok.Timeout, tok.XXX_unrecognized}
	marshalled, err := proto.Marshal(&req)
	check(err)

	// Connect to the module.
	sock, err := net.Dial("unix", aesm_socket)
	defer sock.Close()
	check(err)
	sizBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizBytes, uint32(len(marshalled)))

	n, err := sock.Write(sizBytes)
	check(err)
	if n != 4 {
		panic("Error: writing the size.")
	}
	n, err = sock.Write(marshalled)
	check(err)
	if n != len(marshalled) {
		panic("Error: writing the marshalled data")
	}

	// Get the response.
	limitR := io.LimitReader(sock, 4)
	sizBytes = make([]byte, 4)
	n, err = limitR.Read(sizBytes)
	check(err)
	siz := binary.LittleEndian.Uint32(sizBytes)

	limitRC := io.LimitReader(sock, int64(siz))
	content := make([]byte, siz)
	n, err = limitRC.Read(content)
	check(err)

	// Convert the repsonse.
	response := &Response{}
	proto.Unmarshal(content, response)
	fmt.Println(response)
}
