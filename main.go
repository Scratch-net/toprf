package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	rnd "math/rand/v2"
	"toprf/utils"
)

func main() {

	// OPRF keys
	sk := utils.RandomZ()
	pk := new(utils.Point).ScalarBaseMultInt(sk)

	fmt.Println("pk", pk.X)

	// Threshold params
	peers := 100
	threshold := 99
	shares := CreateShares(peers, threshold, sk)

	// Client blinds his data hash
	a, r := Blind("super secret data")

	// chooses nodes at random
	idxs := pickRandomIndexes(peers, threshold)

	responses := make([]*utils.Point, 0, threshold)

	// talk to Threshold number of nodes
	for i := 0; i < threshold; i++ {
		node := shares[idxs[i]]
		// at node
		response, proof := OPRFEvaluate(node, a)

		// at client
		if !VerifyDLEQ(proof.C, proof.R, node.PublicKey, response, a) {
			panic("DLEQ Proof verification failed!")
		}
		responses = append(responses, response)
	}

	// client recombines evaluated point
	b := TOPRFThresholdMult(idxs, responses)
	unblinded := Unblind(b, r)
	fmt.Println(unblinded.X)

	fmt.Println()

	// recombine public key
	pkShares := make([]*utils.Point, 0, threshold)
	for i := 0; i < threshold; i++ {
		pkShares = append(pkShares, shares[idxs[i]].PublicKey)
	}
	pk = TOPRFThresholdMult(idxs, pkShares)
	fmt.Println("pk", pk.X)

	// try directly without any threshold magic
	b, _ = OPRFEvaluate(&Share{PrivateKey: sk}, a)
	unblinded = Unblind(b, r)
	fmt.Println(unblinded.X)

}

type Src struct{}

func (Src) Uint64() uint64 {
	i, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(math.MaxUint64))
	return i.Uint64()
}

func pickRandomIndexes(n, k int) []int {
	r := rnd.New(Src{})
	idxs := r.Perm(n)
	return idxs[:k]
}
