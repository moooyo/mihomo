package engine

import (
	"context"
	"fmt"

	"github.com/dop251/goja"
)

// executeGuest is reachable only from the hidden worker command. The parent
// coordinator never calls it; it serializes a task through workerController
// instead. Keeping the VM construction here makes the hard boundary auditable.
func (r *scriptRuntime) executeGuest(
	ctx context.Context,
	module Module,
	rule ScriptRule,
	request scriptMessage,
	response *scriptMessage,
) (result scriptResult, err error) {
	defer func() {
		switch recovered := recover().(type) {
		case nil:
		case *goja.Exception, *goja.InterruptedError, *goja.StackOverflowError:
			result = scriptResult{}
			err = fmt.Errorf("extension %s action %s: %v", module.ID, rule.ID, recovered)
		default:
			panic(recovered)
		}
	}()

	if rule.JQProgram != "" {
		return r.executeJQ(ctx, module, rule, request, response)
	}
	program, err := scriptProgram(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	settings, err := scriptSettingValues(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	vm := goja.New()
	if err := hardenScriptVM(vm); err != nil {
		return scriptResult{}, fmt.Errorf("initialize extension runtime: %w", err)
	}
	loop := newAsyncLoop()
	defer loop.close()
	if err := loop.installTimerAPI(vm); err != nil {
		return scriptResult{}, err
	}
	if rule.Entry == scriptEntryProxyCompat {
		if err := installWebAPI(vm); err != nil {
			return scriptResult{}, err
		}
		if err := installDOMAPI(vm); err != nil {
			return scriptResult{}, err
		}
	}
	installConsoleAPI(vm, r.logs, EngineLog{
		Source: "script", Extension: module.ID, Action: rule.ID, Phase: rule.Phase,
		URL: request.URL, ScriptDigest: rule.ScriptDigest,
	})
	requestBodyMode := "none"
	if response == nil {
		requestBodyMode = rule.BodyMode
	}
	requestObject, err := scriptMessageObject(vm, request, requestBodyMode)
	if err != nil {
		return scriptResult{}, err
	}
	contextObject := map[string]any{
		"phase":    rule.Phase,
		"request":  requestObject,
		"settings": settings,
	}
	if response != nil {
		responseObject, objectErr := scriptMessageObject(vm, *response, rule.BodyMode)
		if objectErr != nil {
			return scriptResult{}, objectErr
		}
		contextObject["response"] = responseObject
	}
	if module.PersistentStorage {
		contextObject["storage"] = r.storageObject(vm, module.ID)
	}
	var requester *moduleNetworkRequester
	if module.Network {
		requester = newWorkerModuleNetworkRequester(ctx, r.workerClient, module.ID)
		defer requester.Close()
		if rule.Entry != scriptEntryProxyCompat {
			contextObject["network"] = requester.newAPI(vm, loop)
		}
	}

	stopInterrupt := context.AfterFunc(ctx, func() {
		vm.Interrupt("script execution canceled or timed out")
	})
	defer func() {
		stopInterrupt()
		vm.ClearInterrupt()
	}()

	if rule.Entry == scriptEntryProxyCompat {
		return r.executeProxyCompat(ctx, vm, loop, program, module, rule, settings, requestObject, contextObject, requester, response != nil)
	}
	if _, err := vm.RunProgram(program); err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	transform, ok := goja.AssertFunction(vm.Get("transform"))
	if !ok {
		return scriptResult{}, fmt.Errorf("extension %s action %s must define function transform(context)", module.ID, rule.ID)
	}
	value, err := transform(goja.Undefined(), vm.ToValue(contextObject))
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	settled, err := settlePromise(ctx, vm, loop, value)
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	return parseNativeScriptResult(settled, response != nil)
}

// validateGuestPrograms is likewise worker-only. A candidate document is not
// persisted or published until every untrusted program has compiled here.
func validateGuestPrograms(cfg Config) error {
	for _, module := range cfg.Modules {
		for _, rule := range module.Scripts {
			switch {
			case rule.JQProgram != "":
				if _, err := compileJQProgram(rule.JQProgram); err != nil {
					return fmt.Errorf("extension %q action %q: %w", module.ID, rule.ID, err)
				}
			case rule.ScriptBody != "":
				if _, err := scriptProgram(module, rule); err != nil {
					return fmt.Errorf("extension %q action %q script does not compile: %w", module.ID, rule.ID, err)
				}
			}
		}
	}
	return nil
}
