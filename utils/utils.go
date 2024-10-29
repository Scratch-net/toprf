package utils

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const (
	zLen = 32
)

// Read is a helper function that calls Reader.Read using io.ReadFull.
// On return, n == len(b) if and only if err == nil.
func randRead(b []byte) {
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
}

// hash hashes a slice of byte arrays,
func hash(domain []byte, tuple ...[]byte) []byte {
	hash := sha512.New()
	/* #nosec */
	hash.Write(domain)
	for _, t := range tuple {
		/* #nosec */
		hash.Write(t)
	}
	return hash.Sum(nil)
}

// initKdf creates HKDF instance initialized with hash
func initKdf(domain []byte, tuple ...[]byte) io.Reader {
	key := hash(nil, tuple...)

	return hkdf.New(sha512.New, key, domain, []byte("info"))

}

// RandomZ generates big random 256 bit integer which must be less than curve's N parameter
func RandomZ() (z *big.Int) {
	rz := makeZ(rand.Reader)
	for z == nil {
		// If the scalar is out of range, sample another random number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(rand.Reader)
		} else {
			z = rz
		}
	}
	return
}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func HashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := initKdf(domain, data...)
	rz := makeZ(xof)

	for z == nil {
		// If the scalar is out of range, extract another number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(xof)
		} else {
			z = rz
		}
	}
	return
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, zLen)
	n, err := reader.Read(buf)
	if err != nil || n != zLen {
		panic("random read failed")
	}
	return new(big.Int).SetBytes(buf)
}

// padZ makes all bytes equal size adding zeroes to the beginning if necessary
func padZ(z []byte) []byte {
	if len(z) == zLen {
		return z
	}

	newZ := make([]byte, zLen)
	copy(newZ[zLen-len(z):], z)
	return newZ
}

// hashToPoint maps arrays of bytes to a valid curve point
func hashToPoint(domain []byte, data ...[]byte) *Point {
	h := hash(domain, data...)
	x, y := HashToPoint(h[:PointHashLen])
	return &Point{x, y}
}
