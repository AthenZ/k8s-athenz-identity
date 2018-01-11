package ident

import (
	"fmt"
	"sync"
)

type refCountedLock struct {
	ref  int
	lock *sync.Mutex
}

type idLock struct {
	masterLock sync.Mutex
	locks      map[string]*refCountedLock
}

func newIDLock() *idLock {
	return &idLock{
		locks: make(map[string]*refCountedLock),
	}
}

func (idl *idLock) lockHandle(handle string) (unlock func()) {
	idl.masterLock.Lock()
	entry := idl.locks[handle]
	if entry == nil {
		entry = &refCountedLock{lock: &sync.Mutex{}, ref: 0}
		idl.locks[handle] = entry
	}
	entry.ref++
	idl.masterLock.Unlock()
	entry.lock.Lock()

	return func() {
		idl.unlockHandle(handle)
	}
}

func (idl *idLock) unlockHandle(handle string) {
	idl.masterLock.Lock()
	defer idl.masterLock.Unlock()

	entry := idl.locks[handle]
	if entry == nil {
		panic(fmt.Errorf("no lock found for %s", handle))
	}

	entry.lock.Unlock()
	entry.ref--

	if entry.ref == 0 {
		delete(idl.locks, handle)
	}
}
