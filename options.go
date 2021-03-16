package smt

type Option func(*SparseMerkleTree)

// AutoRemoveOrphans option configures SMT to automatically remove orphaned nodes during Update/Delete operation.
func AutoRemoveOrphans() Option {
	return func(smt *SparseMerkleTree) {
		smt.prune = true
	}
}
