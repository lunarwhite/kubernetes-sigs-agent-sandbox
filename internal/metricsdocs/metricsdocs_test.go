// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsdocs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

// controllerMetricsDir is the package the checked-in reference is built from.
const controllerMetricsDir = "../metrics"

// TestExtractControllerMetrics is the acceptance baseline: it pins what the
// controller actually exposes, so adding, removing or relabelling a metric
// family has to be an explicit change here rather than a silent one.
func TestExtractControllerMetrics(t *testing.T) {
	want := []family{
		{
			Name: "agent_sandbox_build_info",
			Type: typeGauge,
			// Sorted, because they are declared in a map literal.
			ConstLabels: []string{"build_date", "compiler", "git_commit", "git_version", "go_version", "platform"},
		},
		{
			Name:   "agent_sandbox_claim_controller_startup_latency_ms",
			Type:   typeHistogram,
			Labels: []string{"launch_type", "sandbox_template"},
		},
		{
			Name:   "agent_sandbox_claim_creation_total",
			Type:   typeCounter,
			Labels: []string{"namespace", "sandbox_template", "launch_type", "warmpool_name", "pod_condition", "created_by"},
		},
		{
			Name:   "agent_sandbox_claim_startup_latency_ms",
			Type:   typeHistogram,
			Labels: []string{"launch_type", "sandbox_template"},
		},
		{
			Name:   "agent_sandbox_client_claim_startup_latency_ms",
			Type:   typeHistogram,
			Labels: []string{"launch_type", "sandbox_template"},
		},
		{
			Name:   "agent_sandbox_creation_latency_ms",
			Type:   typeHistogram,
			Labels: []string{"namespace", "launch_type", "sandbox_template"},
		},
		{
			// Declared as a bare descriptor, so its Gauge type comes from the
			// MustNewConstMetric call in sandbox_collector.go.
			Name:   "agent_sandboxes",
			Type:   typeGauge,
			Labels: []string{"namespace", "ready_condition", "expired", "launch_type", "sandbox_template", "owned_by", "created_by"},
		},
	}

	got, err := extract(controllerMetricsDir)
	require.NoError(t, err)
	// Help prose is pinned verbatim by the checked-in docs/metrics.md, which the
	// generated-file presubmit regenerates and diffs, and extraction refuses a
	// metric without it. Repeating it here would be a second hand-maintained copy
	// of the same text.
	require.Empty(t, cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.IgnoreFields(family{}, "Help")))
}

func TestGenerateRejectsPackageWithoutMetrics(t *testing.T) {
	source := sourceDir(t, map[string]string{
		"metrics.go": promSource(`var Registry = prometheus.NewRegistry()`),
	})

	err := Generate(source, filepath.Join(t.TempDir(), "metrics.md"))
	require.ErrorContains(t, err, "no metric definitions found")
}

// TestGenerateExtractsBeforeWriting guards the ordering rather than
// the atomic write: extraction must fully succeed before the output is touched,
// so the natural "open the file, write the preamble, then walk the AST" refactor
// cannot truncate a good reference on a bad run.
func TestGenerateExtractsBeforeWriting(t *testing.T) {
	source := sourceDir(t, map[string]string{
		"metrics.go": promSource(`var M = prometheus.NewCounter(prometheus.CounterOpts{Name: metricName, Help: "H."})`),
	})
	output := filepath.Join(t.TempDir(), "metrics.md")
	require.NoError(t, os.WriteFile(output, []byte("previous contents"), 0o600))

	require.Error(t, Generate(source, output))

	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "previous contents", string(got))
}
