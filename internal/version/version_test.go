package version

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	info := Get()
	assert.Equal(t, Version, info.Version)
	assert.Equal(t, GitCommit, info.GitCommit)
	assert.Equal(t, BuildDate, info.BuildDate)
	assert.Equal(t, runtime.Version(), info.GoVersion)
	assert.Equal(t, runtime.GOOS, info.OS)
	assert.Equal(t, runtime.GOARCH, info.Arch)

	str := info.String()
	assert.Contains(t, str, "KryptonMCP")
	assert.Contains(t, str, Version)
	assert.Contains(t, str, runtime.GOOS)
}
