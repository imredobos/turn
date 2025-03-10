package client

import (
	"net"
	"testing"

	"github.com/pion/stun"
	"github.com/stretchr/testify/assert"
)

type dummyUDPConnObserver struct {
	turnServerAddr      net.Addr
	username            stun.Username
	realm               stun.Realm
	_writeTo            func(data []byte, to net.Addr) (int, error)
	_performTransaction func(msg *stun.Message, to net.Addr, dontWait bool) (TransactionResult, error)
	_onDeallocated      func(relayedAddr net.Addr)
}

func (obs *dummyUDPConnObserver) TURNServerAddr() net.Addr {
	return obs.turnServerAddr
}

func (obs *dummyUDPConnObserver) Username() stun.Username {
	return obs.username
}

func (obs *dummyUDPConnObserver) Realm() stun.Realm {
	return obs.realm
}

func (obs *dummyUDPConnObserver) WriteTo(data []byte, to net.Addr) (int, error) {
	if obs._writeTo != nil {
		return obs._writeTo(data, to)
	}
	return 0, nil
}

func (obs *dummyUDPConnObserver) PerformTransaction(msg *stun.Message, to net.Addr, dontWait bool) (TransactionResult, error) {
	if obs._performTransaction != nil {
		return obs._performTransaction(msg, to, dontWait)
	}
	return TransactionResult{}, nil
}

func (obs *dummyUDPConnObserver) OnDeallocated(relayedAddr net.Addr) {
	if obs._onDeallocated != nil {
		obs._onDeallocated(relayedAddr)
	}
}

func TestUDPConn(t *testing.T) {
	t.Run("bind()", func(t *testing.T) {
		obs := &dummyUDPConnObserver{
			_performTransaction: func(msg *stun.Message, to net.Addr, dontWait bool) (TransactionResult, error) {
				return TransactionResult{}, errFake
			},
		}

		bm := newBindingManager()
		b := bm.create(&net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		})

		conn := UDPConn{
			obs:        obs,
			bindingMgr: bm,
		}

		err := conn.bind(b)
		assert.Error(t, err, "should fail")
		assert.Equal(t, 0, len(bm.chanMap), "should be 0")
		assert.Equal(t, 0, len(bm.addrMap), "should be 0")
	})

	t.Run("WriteTo()", func(t *testing.T) {
		obs := &dummyUDPConnObserver{
			_performTransaction: func(msg *stun.Message, to net.Addr, dontWait bool) (TransactionResult, error) {
				return TransactionResult{}, errFake
			},
			_writeTo: func(data []byte, to net.Addr) (int, error) {
				return len(data), nil
			},
		}

		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		}

		pm := newPermissionMap()
		assert.True(t, pm.insert(addr, &permission{
			st: permStatePermitted,
		}))

		bm := newBindingManager()
		binding := bm.create(addr)
		binding.setState(bindingStateReady)

		conn := UDPConn{
			obs:        obs,
			permMap:    pm,
			bindingMgr: bm,
		}

		buf := []byte("Hello")
		n, err := conn.WriteTo(buf, addr)
		assert.NoError(t, err, "should fail")
		assert.Equal(t, len(buf), n)
	})
}
