package main

import (
	"math/big"
	"toprf/utils"
)

type DLProof struct {
	C, R *big.Int
}

// ProveDLEQ x - private key, xG - public key, H - blinded point, xH - evaluated point
func ProveDLEQ(x *big.Int, H *utils.Point) (*DLProof, error) {

	// xG = G*x, xH = H*x
	xG := new(utils.Point).ScalarBaseMultInt(x)
	xH := H.ScalarMultInt(x)
	// random scalar
	v := utils.RandomZ()

	vG := new(utils.Point).ScalarBaseMultInt(v) // G*v

	vH := H.ScalarMultInt(v) // H*v

	basePoint := &utils.Point{
		X: curve.Params().Gx,
		Y: curve.Params().Gy,
	}

	c := HashPointsToScalar(basePoint, xG, vG, vH, H, xH)

	r := new(big.Int).Neg(c) // -c
	r.Mul(r, x)              // -c*x
	r.Add(r, v)              // v - c*x
	r.Mod(r, curve.Params().N)

	return &DLProof{
		C: c,
		R: r,
	}, nil
}

func VerifyDLEQ(c, r *big.Int, xG, xH, H *utils.Point) bool {
	/*
		vG==rG+c(xG)
		vH==rH+c(xH)
	*/

	basePoint := &utils.Point{
		X: curve.Params().Gx,
		Y: curve.Params().Gy,
	}
	rg := new(utils.Point).ScalarBaseMultInt(r) // G * r = G * (v-c*x)
	chg := xG.ScalarMultInt(c)                  // G*x*c

	vG := rg.Add(chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG

	rH := H.ScalarMultInt(r)  // H * r = H * (v-c*x)
	cH := xH.ScalarMultInt(c) // H*x*c

	vH := rH.Add(cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH

	verifyHash := HashPointsToScalar(basePoint, xG, vG, vH, H, xH)
	return verifyHash.Cmp(c) == 0
}

func HashPointsToScalar(points ...*utils.Point) *big.Int {
	var data []byte
	for _, point := range points {
		data = append(data, point.X.Bytes()...)
		data = append(data, point.Y.Bytes()...)
	}
	return utils.HashZ([]byte("DLEQ"), data)
}
