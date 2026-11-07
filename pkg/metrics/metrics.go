// Package metrics is a tiny dependency-free counter registry that renders the
// Prometheus text exposition format.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Registry holds labelled counters.
type Registry struct {
	mu       sync.Mutex
	help     map[string]string
	counters map[string]map[string]uint64 // name -> rendered labels -> value
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{help: map[string]string{}, counters: map[string]map[string]uint64{}}
}

// Describe sets the HELP text of a metric.
func (r *Registry) Describe(name, help string) {
	r.mu.Lock()
	r.help[name] = help
	r.mu.Unlock()
}

// Inc increments a counter by one. labels is an even-length list of key, value pairs.
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

// Add increments a counter by n.
func (r *Registry) Add(name string, n uint64, labels ...string) {
	key := renderLabels(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.counters[name]
	if m == nil {
		m = map[string]uint64{}
		r.counters[name] = m
	}
	m[key] += n
}

// Value returns the current counter value (for tests).
func (r *Registry) Value(name string, labels ...string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counters[name][renderLabels(labels)]
}

// Write renders all counters in Prometheus text format, sorted for stable output.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.counters))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := r.help[n]; h != "" {
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n", n, h); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s counter\n", n); err != nil {
			return err
		}
		keys := make([]string, 0, len(r.counters[n]))
		for k := range r.counters[n] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(w, "%s%s %d\n", n, k, r.counters[n][k]); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderLabels(kv []string) string {
	if len(kv) < 2 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, kv[i], escape(kv[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
