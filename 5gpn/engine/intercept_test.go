package engine

import (
	"reflect"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestInterceptorContractHasNoDatagramSurface(t *testing.T) {
	contract := reflect.TypeOf((*C.Interceptor)(nil)).Elem()
	concrete := reflect.TypeOf((*Interceptor)(nil))
	for _, name := range []string{"MatchUDP", "HandleUDP"} {
		if _, exists := contract.MethodByName(name); exists {
			t.Fatalf("interceptor contract still exposes dormant %s", name)
		}
		if _, exists := concrete.MethodByName(name); exists {
			t.Fatalf("engine interceptor still implements dormant %s", name)
		}
	}
}
