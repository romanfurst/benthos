package buffer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Jeffail/benthos/v3/lib/log"
	"github.com/Jeffail/benthos/v3/lib/message"
	"github.com/Jeffail/benthos/v3/lib/metrics"
	"github.com/Jeffail/benthos/v3/lib/response"
	"github.com/Jeffail/benthos/v3/lib/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamMemoryBuffer(t *testing.T) {
	var incr, total uint8 = 100, 50

	tChan := make(chan types.Transaction)
	resChan := make(chan types.Response)

	b := NewStream("meow", newMemoryBuffer(int(total)), log.Noop(), metrics.Noop())
	require.NoError(t, b.Consume(tChan))

	var i uint8

	// Check correct flow no blocking
	for ; i < total; i++ {
		msgBytes := make([][]byte, 1)
		msgBytes[0] = make([]byte, int(incr))
		msgBytes[0][0] = i

		select {
		// Send to buffer
		case tChan <- types.NewTransaction(message.QuickBatch(msgBytes), resChan):
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for unbuffered message %v send", i)
		}

		// Instant response from buffer
		select {
		case res := <-resChan:
			require.NoError(t, res.AckError())
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for unbuffered message %v response", i)
		}

		// Receive on output
		var outTr types.Transaction
		select {
		case outTr = <-b.TransactionChan():
			assert.Equal(t, i, outTr.Payload.Get(0).Get()[0])
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for unbuffered message %v read", i)
		}

		// Response from output
		select {
		case outTr.ResponseChan <- response.NewAck():
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for unbuffered response send back %v", i)
		}
	}

	for i = 0; i <= total; i++ {
		msgBytes := make([][]byte, 1)
		msgBytes[0] = make([]byte, int(incr))
		msgBytes[0][0] = i

		select {
		case tChan <- types.NewTransaction(message.QuickBatch(msgBytes), resChan):
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered message %v send", i)
		}
		select {
		case res := <-resChan:
			assert.NoError(t, res.AckError())
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered message %v response", i)
		}
	}

	// Should have reached limit here
	msgBytes := make([][]byte, 1)
	msgBytes[0] = make([]byte, int(incr)+1)

	select {
	case tChan <- types.NewTransaction(message.QuickBatch(msgBytes), resChan):
	case <-time.After(time.Second):
		t.Fatalf("Timed out waiting for final buffered message send")
	}

	// Response should block until buffer is relieved
	select {
	case res := <-resChan:
		if res.AckError() != nil {
			t.Fatal(res.AckError())
		} else {
			t.Fatalf("Overflowed response returned before timeout")
		}
	case <-time.After(100 * time.Millisecond):
	}

	var outTr types.Transaction

	// Extract last message
	select {
	case outTr = <-b.TransactionChan():
		assert.Equal(t, byte(0), outTr.Payload.Get(0).Get()[0])
		outTr.ResponseChan <- response.NewAck()
	case <-time.After(time.Second):
		t.Fatalf("Timed out waiting for final buffered message read")
	}

	// Response from the last attempt should no longer be blocking
	select {
	case res := <-resChan:
		assert.NoError(t, res.AckError())
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Final buffered response blocked")
	}

	// Extract all other messages
	for i = 1; i <= total; i++ {
		select {
		case outTr = <-b.TransactionChan():
			assert.Equal(t, i, outTr.Payload.Get(0).Get()[0])
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered message %v read", i)
		}

		select {
		case outTr.ResponseChan <- response.NewAck():
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered response send back %v", i)
		}
	}

	// Get final message
	select {
	case outTr = <-b.TransactionChan():
	case <-time.After(time.Second):
		t.Fatalf("Timed out waiting for buffered message %v read", i)
	}

	select {
	case outTr.ResponseChan <- response.NewAck():
	case <-time.After(time.Second):
		t.Fatalf("Timed out waiting for buffered response send back %v", i)
	}

	b.CloseAsync()
	require.NoError(t, b.WaitForClose(time.Second))

	close(resChan)
	close(tChan)
}

func TestStreamBufferClosing(t *testing.T) {
	var incr, total uint8 = 100, 5

	tChan := make(chan types.Transaction)
	resChan := make(chan types.Response)

	b := NewStream("meow", newMemoryBuffer(int(total)), log.Noop(), metrics.Noop())
	require.NoError(t, b.Consume(tChan))

	var i uint8

	// Populate buffer with some messages
	for i = 0; i < total; i++ {
		msgBytes := make([][]byte, 1)
		msgBytes[0] = make([]byte, int(incr))
		msgBytes[0][0] = i

		select {
		case tChan <- types.NewTransaction(message.QuickBatch(msgBytes), resChan):
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered message %v send", i)
		}
		select {
		case res := <-resChan:
			assert.NoError(t, res.AckError())
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for buffered message %v response", i)
		}
	}

	// Close input, this should prompt the stack buffer to Flush().
	close(tChan)

	// Receive all of those messages from the buffer
	for i = 0; i < total; i++ {
		select {
		case val := <-b.TransactionChan():
			assert.Equal(t, i, val.Payload.Get(0).Get()[0])
			val.ResponseChan <- response.NewAck()
		case <-time.After(time.Second):
			t.Fatalf("Timed out waiting for final buffered message read")
		}
	}

	// The buffer should now be closed, therefore so should our read channel.
	select {
	case _, open := <-b.TransactionChan():
		assert.False(t, open)
	case <-time.After(time.Second):
		t.Fatalf("Timed out waiting for final buffered message read")
	}

	// Should already be shut down.
	assert.NoError(t, b.WaitForClose(time.Second))
}

//------------------------------------------------------------------------------

type readErrorBuffer struct {
	readErrs chan error
}

func (r *readErrorBuffer) Read(ctx context.Context) (*message.Batch, AckFunc, error) {
	select {
	case err := <-r.readErrs:
		return nil, nil, err
	default:
	}
	return message.QuickBatch([][]byte{[]byte("hello world")}), func(c context.Context, e error) error {
		return nil
	}, nil
}

func (r *readErrorBuffer) Write(ctx context.Context, msg *message.Batch, aFn AckFunc) error {
	return aFn(context.Background(), nil)
}

func (r *readErrorBuffer) EndOfInput() {
}

func (r *readErrorBuffer) Close(ctx context.Context) error {
	return nil
}

func TestStreamReadErrors(t *testing.T) {
	tChan := make(chan types.Transaction)
	resChan := make(chan types.Response)

	errBuf := &readErrorBuffer{
		readErrs: make(chan error, 2),
	}
	errBuf.readErrs <- errors.New("first error")
	errBuf.readErrs <- errors.New("second error")

	b := NewStream("meow", errBuf, log.Noop(), metrics.Noop())
	require.NoError(t, b.Consume(tChan))

	var tran types.Transaction
	select {
	case tran = <-b.TransactionChan():
	case <-time.After(time.Second * 5):
		t.Fatal("timed out")
	}

	require.Equal(t, 1, tran.Payload.Len())
	assert.Equal(t, "hello world", string(tran.Payload.Get(0).Get()))

	select {
	case tran.ResponseChan <- response.NewAck():
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}

	b.CloseAsync()
	require.NoError(t, b.WaitForClose(time.Second))

	close(resChan)
	close(tChan)
}
