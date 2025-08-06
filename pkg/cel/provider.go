package cel

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
)

// Ensure our custom type implements the required traits.
var execEventType = types.NewTypeValue("ExecEvent", traits.ReceiverType)

// execEventValue is a CEL value representing our ExecEvent struct.
// It will implement the `ref.Val` interface.
type execEventValue struct {
	*events.ExecEvent
	sync.Once
}

func (v *execEventValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	if typeDesc == reflect.TypeOf(v.ExecEvent) {
		return v.ExecEvent, nil
	}
	return nil, fmt.Errorf("type conversion failed")
}

func (v *execEventValue) ConvertToType(typeVal ref.Type) ref.Val {
	// Not needed for this example, but you would handle conversions here.
	return types.NewErr("unsupported conversion")
}

func (v *execEventValue) Equal(other ref.Val) ref.Val {
	// Simple equality check
	_, ok := other.Value().(*events.ExecEvent)
	if !ok {
		return types.ValOrErr(other, "not a ExecEvent type")
	}
	return types.Bool(false)
}

func (v *execEventValue) Type() ref.Type {
	return execEventType
}

func (v *execEventValue) Value() interface{} {
	return v.ExecEvent
}

// Receive is where the magic happens. We handle function calls here.
// This is the core of avoiding reflection.
func (v *execEventValue) Receive(function string, overload string, args []ref.Val) ref.Val {
	switch function {
	//case "is_admin":
	//	// Direct method call, no reflection.
	//	return types.Bool(v.Email == "admin@example.com")
	default:
		return types.ValOrErr(execEventType, "no such function - %s", function)
	}
}

func (v *execEventValue) HasTrait(trait int) bool {
	return trait == traits.ReceiverType
}

// customTypeAdapter converts a native Go value to a CEL value.
type customTypeAdapter struct{}

func (customTypeAdapter) NativeToValue(value interface{}) ref.Val {
	if u, ok := value.(*events.ExecEvent); ok {
		return &execEventValue{ExecEvent: u}
	}
	// Fall back to the default adapter for other types.
	return types.DefaultTypeAdapter.NativeToValue(value)
}

// customTypeProvider defines the types and functions available in CEL.
type customTypeProvider struct {
	types.Provider
}

// FindIdent returns a value by qualified identifier name.
func (p *customTypeProvider) FindIdent(identName string) (ref.Val, bool) {
	switch identName {
	case "data.event.runtime.containerId":
		return p.Provider.FindIdent(identName)
	default:
		return p.Provider.FindIdent(identName)
	}
}
