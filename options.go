package smt

// Option is a function that configures SparseMerkleTree.
type Option func(*SMT)

func WithPathHasher(ph PathHasher) Option {
	return func(smt *SMT) { smt.ph = ph }
}

func WithValueHasher(vh ValueHasher) Option {
	return func(smt *SMT) { smt.vh = vh }
}
