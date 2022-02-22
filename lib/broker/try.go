package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Jeffail/benthos/v3/internal/component"
	"github.com/Jeffail/benthos/v3/internal/component/output"
	"github.com/Jeffail/benthos/v3/lib/metrics"
	"github.com/Jeffail/benthos/v3/lib/types"
)

//------------------------------------------------------------------------------

// Try is a broker that implements types.Consumer and attempts to send each
// message to a single output, but on failure will attempt the next output in
// the list.
type Try struct {
	stats         metrics.Type
	outputsPrefix string

	maxInFlight  int
	transactions <-chan types.Transaction

	outputTSChans []chan types.Transaction
	outputs       []types.Output

	ctx        context.Context
	close      func()
	closedChan chan struct{}
}

// NewTry creates a new Try type by providing consumers.
func NewTry(outputs []types.Output, stats metrics.Type) (*Try, error) {
	ctx, done := context.WithCancel(context.Background())
	t := &Try{
		maxInFlight:   1,
		stats:         stats,
		outputsPrefix: "broker.outputs",
		transactions:  nil,
		outputs:       outputs,
		closedChan:    make(chan struct{}),
		ctx:           ctx,
		close:         done,
	}
	if len(outputs) == 0 {
		return nil, errors.New("missing outputs")
	}
	t.outputTSChans = make([]chan types.Transaction, len(t.outputs))
	for i := range t.outputTSChans {
		t.outputTSChans[i] = make(chan types.Transaction)
		if err := t.outputs[i].Consume(t.outputTSChans[i]); err != nil {
			return nil, err
		}
		if mif, ok := output.GetMaxInFlight(t.outputs[i]); ok && mif > t.maxInFlight {
			t.maxInFlight = mif
		}
	}
	return t, nil
}

//------------------------------------------------------------------------------

// WithMaxInFlight sets the maximum number of in-flight messages this broker
// supports. This must be set before calling Consume.
func (t *Try) WithMaxInFlight(i int) *Try {
	if i < 1 {
		i = 1
	}
	t.maxInFlight = i
	return t
}

// WithOutputMetricsPrefix changes the prefix used for counter metrics showing
// errors of an output.
func (t *Try) WithOutputMetricsPrefix(prefix string) *Try {
	t.outputsPrefix = prefix
	return t
}

// Consume assigns a new messages channel for the broker to read.
func (t *Try) Consume(ts <-chan types.Transaction) error {
	if t.transactions != nil {
		return component.ErrAlreadyStarted
	}
	t.transactions = ts

	go t.loop()
	return nil
}

// Connected returns a boolean indicating whether this output is currently
// connected to its target.
func (t *Try) Connected() bool {
	for _, out := range t.outputs {
		if !out.Connected() {
			return false
		}
	}
	return true
}

// MaxInFlight returns the maximum number of in flight messages permitted by the
// output. This value can be used to determine a sensible value for parent
// outputs, but should not be relied upon as part of dispatcher logic.
func (t *Try) MaxInFlight() (int, bool) {
	return t.maxInFlight, true
}

//------------------------------------------------------------------------------

// loop is an internal loop that brokers incoming messages to many outputs.
func (t *Try) loop() {
	var (
		wg        = sync.WaitGroup{}
		mMsgsRcvd = t.stats.GetCounter("count")
		mErrs     = []metrics.StatCounter{}
	)

	defer func() {
		wg.Wait()
		for _, c := range t.outputTSChans {
			close(c)
		}
		closeAllOutputs(t.outputs)
		close(t.closedChan)
	}()

	for i := range t.outputs {
		mErrs = append(mErrs, t.stats.GetCounter(fmt.Sprintf("%v.%v.failed", t.outputsPrefix, i)))
	}

	sendLoop := func() {
		defer wg.Done()
		for {
			var open bool
			var tran types.Transaction

			select {
			case tran, open = <-t.transactions:
				if !open {
					return
				}
			case <-t.ctx.Done():
				return
			}
			mMsgsRcvd.Incr(1)

			rChan := make(chan types.Response)
			select {
			case t.outputTSChans[0] <- types.NewTransaction(tran.Payload, rChan):
			case <-t.ctx.Done():
				return
			}

			var res types.Response
			var lOpen bool

		triesLoop:
			for i := 1; i <= len(t.outputTSChans); i++ {
				select {
				case res, lOpen = <-rChan:
					if !lOpen {
						return
					}
					if res.Error() != nil {
						mErrs[i-1].Incr(1)
					} else {
						break triesLoop
					}
				case <-t.ctx.Done():
					return
				}

				if i < len(t.outputTSChans) {
					select {
					case t.outputTSChans[i] <- types.NewTransaction(tran.Payload, rChan):
					case <-t.ctx.Done():
						return
					}
				}
			}
			select {
			case tran.ResponseChan <- res:
			case <-t.ctx.Done():
				return
			}
		}
	}

	// Max in flight
	for i := 0; i < t.maxInFlight; i++ {
		wg.Add(1)
		go sendLoop()
	}
}

// CloseAsync shuts down the Try broker and stops processing requests.
func (t *Try) CloseAsync() {
	t.close()
}

// WaitForClose blocks until the Try broker has closed down.
func (t *Try) WaitForClose(timeout time.Duration) error {
	select {
	case <-t.closedChan:
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
