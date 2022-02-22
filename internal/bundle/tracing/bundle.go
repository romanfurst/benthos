package tracing

import (
	"github.com/Jeffail/benthos/v3/internal/bundle"
	"github.com/Jeffail/benthos/v3/lib/input"
	"github.com/Jeffail/benthos/v3/lib/output"
	"github.com/Jeffail/benthos/v3/lib/processor"
	"github.com/Jeffail/benthos/v3/lib/types"
)

// TracedBundle modifies a provided bundle environment so that traceable
// components are wrapped by components that add trace events to the returned
// summary.
func TracedBundle(b *bundle.Environment) (*bundle.Environment, *Summary) {
	summary := NewSummary()
	tracedEnv := b.Clone()

	for _, spec := range b.InputDocs() {
		_ = tracedEnv.InputAdd(func(conf input.Config, nm bundle.NewManagement, pcf ...types.PipelineConstructorFunc) (input.Type, error) {
			i, err := b.InputInit(conf, nm, pcf...)
			if err != nil {
				return nil, err
			}
			iEvents, ctr := summary.wInputEvents(nm.Label())
			i = traceInput(iEvents, ctr, i)
			return i, err
		}, spec)
	}

	for _, spec := range b.ProcessorDocs() {
		_ = tracedEnv.ProcessorAdd(func(conf processor.Config, nm bundle.NewManagement) (processor.Type, error) {
			i, err := b.ProcessorInit(conf, nm)
			if err != nil {
				return nil, err
			}
			pEvents, errCtr := summary.wProcessorEvents(nm.Label())
			i = traceProcessor(pEvents, errCtr, i)
			return i, err
		}, spec)
	}

	for _, spec := range b.OutputDocs() {
		_ = tracedEnv.OutputAdd(func(conf output.Config, nm bundle.NewManagement, pcf ...types.PipelineConstructorFunc) (output.Type, error) {
			pcf = output.AppendProcessorsFromConfig(conf, nm, nm.Logger(), nm.Metrics(), pcf...)
			conf.Processors = nil

			o, err := b.OutputInit(conf, nm)
			if err != nil {
				return nil, err
			}

			oEvents, ctr := summary.wOutputEvents(nm.Label())
			o = traceOutput(oEvents, ctr, o)

			return output.WrapWithPipelines(o, pcf...)
		}, spec)
	}

	return tracedEnv, summary
}
