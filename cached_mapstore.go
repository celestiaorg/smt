package smt

// CommitMapStore composes a Commit interface with a MapStore interface
type CommitMapStore interface {
	MapStore
	Commit() error
}

var _ CommitMapStore = &CachedMapStore{}

// CachedMapStore wraps another (persistent) MapStore with an in-memory cache
type CachedMapStore struct {
	cache   map[string]operation // map of key to operation
	deletes map[string]struct{}
	db      MapStore
}

type operation = []byte

// NewCachedMap creates a new empty CachedMapStore.
func NewCachedMap(db MapStore, limit uint64) *CachedMapStore {
	return &CachedMapStore{
		cache:   make(map[string]operation, limit),
		deletes: map[string]struct{}{},
		db:      db,
	}
}

// Get gets the value for a key.
func (cm *CachedMapStore) Get(key []byte) ([]byte, error) {
	if op, ok := cm.cache[string(key)]; ok {
		return op, nil
	}
	if _, has := cm.deletes[string(key)]; has {
		return nil, &InvalidKeyError{Key: key}
	}
	return cm.db.Get(key)
}

// Set updates the value for a key.
func (cm *CachedMapStore) Set(key []byte, value []byte) error {
	cm.cache[string(key)] = value
	return nil
}

// Delete deletes a key.
func (cm *CachedMapStore) Delete(key []byte) error {
	// if it's in the cache, just remove it; otherwise send a delete to the db
	if _, has := cm.cache[string(key)]; has {
		delete(cm.cache, string(key))
	} else {
		cm.deletes[string(key)] = struct{}{}
	}
	return nil
}

func (cm *CachedMapStore) Commit() error {
	for k, _ := range cm.deletes {
		if err := cm.db.Delete([]byte(k)); err != nil {
			return err
		}
	}
	for k, op := range cm.cache {
		key := []byte(k)
		if err := cm.db.Set(key, op); err != nil {
			return err
		}
	}
	cm.cache = map[string]operation{}
	return nil
}
