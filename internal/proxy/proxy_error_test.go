package proxy

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write failure")
}

func TestGatewayProxy_WriterErrors(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, downstreamOutPipeW := io.Pipe()

	proxy := NewGatewayProxy(nil, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     &errorWriter{},
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	// Add interceptor that responds
	proxy.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
		resp, _ := mcp.NewSuccessResponse(mcp.NewIntID(1), "ok")
		return resp, true, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	req, _ := mcp.NewRequest(mcp.NewIntID(1), "test", nil)
	_ = clientWriter.WriteMessage(req)

	err := <-errCh
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write intercepted response")

	_ = downstreamInPipeR
	_ = downstreamOutPipeW
}

func TestGatewayProxy_UninitializedStreamsError(t *testing.T) {
	proxy := &GatewayProxy{}
	err := proxy.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstream reader and writer must be initialized")
}
