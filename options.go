package smt

// Option is a function that configures SMT.
type Option func(*SparseMerkleTree)

func SetPathHasher(ph PathHasher) Option {
	return func(smt *SparseMerkleTree) { smt.ph = ph }
}
