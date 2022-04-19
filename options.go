package smt

// Option is a function that configures SparseMerkleTree.
type Option func(*BaseSMT)

func SetPathHasher(ph PathHasher) Option {
	return func(smt *BaseSMT) { smt.ph = ph }
}

func SetValueHasher(vh ValueHasher) Option {
	return func(smt *BaseSMT) { smt.vh = vh }
}
