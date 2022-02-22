package tracing

import (
	"sync/atomic"
	"time"

	"github.com/Jeffail/benthos/v3/internal/shutdown"
	"github.com/Jeffail/benthos/v3/lib/message"
	"github.com/Jeffail/benthos/v3/lib/types"
)

type tracedInput struct {
	e       *events
	ctr     *uint64
	wrapped types.Input
	tChan   chan types.Transaction
	shutSig *shutdown.Signaller
}

func traceInput(e *events, counter *uint64, i types.Input) types.Input {
	t := &tracedInput{
		e:       e,
		ctr:     counter,
		wrapped: i,
		tChan:   make(chan types.Transaction),
		shutSig: shutdown.NewSignaller(),
	}
	go t.loop()
	return t
}

func (t *tracedInput) loop() {
	defer close(t.tChan)
	readChan := t.wrapped.TransactionChan()
	for {
		tran, open := <-readChan
		if !open {
			return
		}
		_ = tran.Payload.Iter(func(i int, part *message.Part) error {
			_ = atomic.AddUint64(t.ctr, 1)
			t.e.Add(EventProduce, string(part.Get()))
			return nil
		})
		select {
		case t.tChan <- tran:
		case <-t.shutSig.CloseNowChan():
			// Stop flushing if we fully timed out
			return
		}
	}
}

func (t *tracedInput) TransactionChan() <-chan types.Transaction {
	return t.tChan
}

func (t *tracedInput) Connected() bool {
	return t.wrapped.Connected()
}

func (t *tracedInput) CloseAsync() {
	t.wrapped.CloseAsync()
}

func (t *tracedInput) WaitForClose(timeout time.Duration) error {
	err := t.wrapped.WaitForClose(timeout)
	t.shutSig.CloseNow()
	return err
}
