package metrics

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistryRender(t *testing.T) {
	r := NewRegistry()
	r.Describe("req_total", "requests")
	r.Inc("req_total", "path", "/rpc", "code", "200")
	r.Inc("req_total", "path", "/rpc", "code", "200")
	r.Inc("req_total", "path", `/a"b`, "code", "401")
	assert.Equal(t, uint64(2), r.Value("req_total", "path", "/rpc", "code", "200"))
	var b bytes.Buffer
	assert.NoError(t, r.Write(&b))
	assert.Equal(t, "# HELP req_total requests\n# TYPE req_total counter\n"+
		"req_total{path=\"/a\\\"b\",code=\"401\"} 1\n"+
		"req_total{path=\"/rpc\",code=\"200\"} 2\n", b.String())
}
