package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	fivegpn "github.com/metacubex/mihomo/5gpn"
	"github.com/metacubex/mihomo/common/cmd"
	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/generator"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/provider"

	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version                       bool
	testConfig                    bool
	geodataMode                   bool
	homeDir                       string
	configFile                    string
	configString                  string
	configBytes                   []byte
	ageSecretKey                  string
	externalUI                    string
	externalController            string
	externalControllerTLS         string
	externalControllerUnix        string
	externalControllerPipe        string
	externalControllerRoutingMark int
	secret                        string
	postUp                        string
	postDown                      string
)

func getIntEnv(key string) int {
	value := os.Getenv(key)
	intValue, _ := strconv.Atoi(value)
	return intValue
}

func init() {
	flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&configString, "config", os.Getenv("CLASH_CONFIG_STRING"), "specify base64-encoded configuration string")
	flag.StringVar(&ageSecretKey, "age-secret-key", os.Getenv("CLASH_AGE_SECRET_KEY"), "specify age secret key to decrypt configuration")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	flag.StringVar(&externalControllerTLS, "ext-ctl-tls", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS"), "override external controller tls address")
	flag.StringVar(&externalControllerUnix, "ext-ctl-unix", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX"), "override external controller unix address")
	flag.StringVar(&externalControllerPipe, "ext-ctl-pipe", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE"), "override external controller pipe address")
	flag.IntVar(&externalControllerRoutingMark, "ext-ctl-routing-mark", getIntEnv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK"), "override external controller routing mark")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	flag.StringVar(&postUp, "post-up", os.Getenv("CLASH_POST_UP"), "set post-up script")
	flag.StringVar(&postDown, "post-down", os.Getenv("CLASH_POST_DOWN"), "set post-down script")
	flag.BoolVar(&geodataMode, "m", false, "set geodata mode")
	flag.BoolVar(&version, "v", false, "show current version of mihomo")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
}

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	if len(os.Args) > 1 && os.Args[1] == fivegpn.ContainerContractCommand() {
		return fivegpn.ContainerContractMain(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == fivegpn.ExtensionWorkerCommand() {
		return fivegpn.ExtensionWorkerMain(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "5gpn-state" {
		fivegpn.StateMain(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "5gpn-config" {
		fivegpn.ConfigInspectMain(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "5gpn-nodes" {
		fivegpn.NodesMain(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "convert-ruleset" {
		provider.ConvertMain(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "generate" {
		generator.Main(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "age" {
		age.Main(os.Args[2:])
		return
	}

	// init only registers application flags. Test binaries register their
	// -test.* flags after package initialization, so parsing there makes the
	// root package impossible to test. Same-binary one-shot modes deliberately
	// dispatch above this ordinary-runtime boundary.
	flag.Parse()

	// Defensive programming: panic when code mistakenly calls net.DefaultResolver
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//panic("should never be called")
		buf := make([]byte, 1024)
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		fmt.Fprintf(os.Stderr, "panic: should never be called\n\n%s", buf) // always print all goroutine stack
		os.Exit(2)
		return nil, nil
	}

	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))

	if version {
		fmt.Printf("Mihomo Meta %s %s %s with %s %s\n",
			C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		if tags := features.Tags(); len(tags) != 0 {
			fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
		}

		return
	}

	termSource := make(chan os.Signal, 1)
	termSign := make(chan struct{}, 1)
	hupSign := make(chan os.Signal, 1)
	if !testConfig {
		termRelayStop := make(chan struct{})
		signal.Notify(termSource, syscall.SIGINT, syscall.SIGTERM)
		signal.Notify(hupSign, syscall.SIGHUP)
		go relayRuntimeTermination(termSource, termSign, termRelayStop, hub.ArmFiveGPNExitWatchdog)
		defer func() {
			close(termRelayStop)
			signal.Stop(termSource)
			signal.Stop(hupSign)
		}()
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if geodataMode {
		geodata.SetGeodataMode(true)
	}

	if ageSecretKey != "" {
		if err := age.VeritySecretKeys(ageSecretKey); err != nil {
			log.Errorln("Parse age-secret-key error: %s", err.Error())
		}
		age.SetGlobalSecretKeys(ageSecretKey)
	}

	if configString != "" {
		var err error
		configBytes, err = base64.StdEncoding.DecodeString(configString)
		if err != nil {
			log.Errorln("Initial configuration error: %s", err.Error())
			return 1
		}
	} else if configFile == "-" {
		var err error
		configBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Errorln("Initial configuration error: %s", err.Error())
			return 1
		}
	} else {
		if configFile != "" {
			if !filepath.IsAbs(configFile) {
				currentDir, _ := os.Getwd()
				configFile = filepath.Join(currentDir, configFile)
			}
		} else {
			configFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		}
		C.SetConfig(configFile)

		if err := config.Init(C.Path.HomeDir()); err != nil {
			log.Errorln("Initial configuration directory error: %s", err.Error())
			return 1
		}
	}

	if testConfig {
		if len(configBytes) != 0 {
			if _, err := executor.ParseWithBytes(configBytes); err != nil {
				log.Errorln("%s", err.Error())
				fmt.Println("configuration test failed")
				return 1
			}
		} else {
			if _, err := executor.Parse(); err != nil {
				log.Errorln("%s", err.Error())
				fmt.Printf("configuration file %s test failed\n", C.Path.Config())
				return 1
			}
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return
	}

	var options []hub.Option
	if externalUI != "" {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if externalControllerTLS != "" {
		options = append(options, hub.WithExternalControllerTLS(externalControllerTLS))
	}
	if externalControllerUnix != "" {
		options = append(options, hub.WithExternalControllerUnix(externalControllerUnix))
	}
	if externalControllerPipe != "" {
		options = append(options, hub.WithExternalControllerPipe(externalControllerPipe))
	}
	if externalControllerRoutingMark != 0 {
		options = append(options, hub.WithExternalControllerRoutingMark(externalControllerRoutingMark))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	postDownReady := false
	defer func() {
		finishRuntimeExit(shutdownRuntime, func() {
			if postDownReady && postDown != "" && !hub.FiveGPNFatalPending() {
				if _, err := cmd.ExecShell(postDown); err != nil {
					log.Errorln("post-down script error: %s", err.Error())
				}
			}
		})
		if hub.FiveGPNFatalPending() {
			exitCode = 1
		}
	}()

	if exit, ready := pollRuntimeExit(termSign, hub.FiveGPNFatalEvents(), hub.FiveGPNRestartEvents()); ready {
		logRuntimeExit(exit)
		return runtimeExitCode(exit)
	}
	if err := hub.ParseManaged(configBytes, options...); err != nil {
		log.Errorln("Parse config error: %s", err.Error())
		return 1
	}
	if exit, ready := pollRuntimeExit(termSign, hub.FiveGPNFatalEvents(), hub.FiveGPNRestartEvents()); ready {
		logRuntimeExit(exit)
		return runtimeExitCode(exit)
	}

	if updater.GeoAutoUpdate() {
		updater.RegisterGeoUpdater()
	}
	if exit, ready := pollRuntimeExit(termSign, hub.FiveGPNFatalEvents(), hub.FiveGPNRestartEvents()); ready {
		logRuntimeExit(exit)
		return runtimeExitCode(exit)
	}

	postDownReady = true
	if postUp != "" {
		if _, err := cmd.ExecShell(postUp); err != nil {
			log.Errorln("post-up script error: %s", err.Error())
			if exit, ready := pollRuntimeExit(termSign, hub.FiveGPNFatalEvents(), hub.FiveGPNRestartEvents()); ready {
				logRuntimeExit(exit)
				if exit.fatal != nil || exit.restart {
					postDownReady = false
				}
			}
			return 1
		}
	}
	exit := waitForRuntimeExit(termSign, hupSign, hub.FiveGPNFatalEvents(), hub.FiveGPNRestartEvents(), func() {
		if err := hub.ParseManaged(configBytes, options...); err != nil {
			log.Errorln("Parse config error: %s", err.Error())
		}
	})
	logRuntimeExit(exit)
	if exit.fatal != nil || exit.restart {
		// A critical failure or explicit supervisor restart must not be held by
		// an arbitrary operator post-down shell. SIGTERM retains the historical
		// post-down behavior and still has an external stop deadline.
		postDownReady = false
	}
	return runtimeExitCode(exit)
}
