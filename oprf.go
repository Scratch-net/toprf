package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"toprf/utils"
)

var curve = elliptic.P256()
var gf = utils.GF{P: curve.Params().N}

func Blind(data string) (*utils.Point, *big.Int) {
	h := sha256.Sum256([]byte(data))
	ax, ay := utils.HashToPoint(h[:])
	a := &utils.Point{
		X: ax,
		Y: ay,
	}
	r := utils.RandomZ()
	b := a.ScalarMultInt(r)

	return b, r
}

func Unblind(b *utils.Point, r *big.Int) *utils.Point {
	rInv := gf.Inv(r)
	return b.ScalarMultInt(rInv)
}

type Share struct {
	Index      int
	PrivateKey *big.Int
	PublicKey  *utils.Point
}

func CreateShares(n, threshold int, secret *big.Int) []*Share {
	a := make([]*big.Int, threshold-1)
	for i := 0; i < threshold-1; i++ {
		a[i] = utils.RandomZ()
	}

	shares := make([]*Share, n)
	// f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(k−1)*x^(k−1)
	for i := 0; i < n; i++ {
		shareIndex := i + 1
		x := big.NewInt(int64(shareIndex))
		shares[i] = &Share{
			Index: shareIndex,
		}

		shares[i].PrivateKey = new(big.Int).Set(secret)
		for j := 0; j < threshold-1; j++ {
			tmp := gf.Mul(a[j], x)
			for exp := 0; exp < j; exp++ {
				tmp = gf.Mul(tmp, x)
			}
			shares[i].PrivateKey = gf.Add(tmp, shares[i].PrivateKey)
		}
		shares[i].PublicKey = OPRFEvaluateBase(shares[i].PrivateKey)
	}

	return shares
}

func OPRFEvaluate(share *Share, blinded *utils.Point) (*utils.Point, *DLProof) {
	xH := blinded.ScalarMultInt(share.PrivateKey)
	proof, err := ProveDLEQ(share.PrivateKey, blinded)
	if err != nil {
		panic(err)
	}

	return xH, proof
}

func OPRFEvaluateBase(k *big.Int) *utils.Point {
	return new(utils.Point).ScalarBaseMultInt(k)
}

// Coeff calculates Lagrange coefficient for node with index idx
func Coeff(idx int, peers []int) *big.Int {

	peerLen := len(peers)
	iScalar := big.NewInt(int64(idx))
	divident := big.NewInt(1)
	divisor := big.NewInt(1)

	for i := 0; i < peerLen; i++ {
		if peers[i] == idx {
			continue
		}
		tmp := big.NewInt(int64(peers[i]))
		divident = gf.Mul(divident, tmp)
		tmp = gf.Sub(tmp, iScalar)
		divisor = gf.Mul(divisor, tmp)
	}
	divisor = gf.Inv(divisor)
	return gf.Mul(divisor, divident)
}

func TOPRFThresholdMult(idxs []int, responses []*utils.Point) *utils.Point {

	peers := make([]int, len(idxs))
	for i := 0; i < len(idxs); i++ {
		peers[i] = idxs[i] + 1
	}
	result := &utils.Point{
		X: big.NewInt(0),
		Y: big.NewInt(0),
	}

	for i := 0; i < len(responses); i++ {
		lPoly := Coeff(peers[i], peers)
		gki := responses[i].ScalarMultInt(lPoly)
		result = result.Add(gki)
	}
	return result
}

// these two are used when nodes know about each other
// func TOPRFEvaluate(k *big.Int, blinded *utils.Point, self int, indexes []int) *utils.Point {
// 	poly := Coeff(self, indexes)
// 	kl := gf.Mul(k, poly)
// 	H, _ := OPRFEvaluate(kl, blinded)
// 	return H
// }
//
// func TOPRFThresholdCombine(responses []*utils.Point) *utils.Point {
// 	result := &utils.Point{
// 		X: big.NewInt(0),
// 		Y: big.NewInt(0),
// 	}
//
// 	for i := 0; i < len(responses); i++ {
// 		result = result.Add(responses[i])
// 	}
// 	return result
// }
