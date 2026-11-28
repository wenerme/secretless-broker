package entrypoint

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/cyberark/secretless-broker/internal"
	"github.com/cyberark/secretless-broker/internal/configurationmanagers/configfile"
	"github.com/cyberark/secretless-broker/internal/configurationmanagers/kubernetes/crd"
	secretlessLog "github.com/cyberark/secretless-broker/internal/log"
	"github.com/cyberark/secretless-broker/internal/plugin/v1/eventnotifier"
	"github.com/cyberark/secretless-broker/internal/profile"
	"github.com/cyberark/secretless-broker/internal/proxyservice"
	"github.com/cyberark/secretless-broker/internal/signal"
	"github.com/cyberark/secretless-broker/internal/telemetry"
	"github.com/cyberark/secretless-broker/internal/util"
	"github.com/cyberark/secretless-broker/pkg/secretless"
	v2 "github.com/cyberark/secretless-broker/pkg/secretless/config/v2"
	logapi "github.com/cyberark/secretless-broker/pkg/secretless/log"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/sharedobj"
)

const telemetryShutdownTimeout = 5 * time.Second

// SecretlessOptions holds the command line flag information that Service was
// started with.
type SecretlessOptions struct {
	ConfigFile          string
	ConfigManagerSpec   string
	DebugEnabled        bool
	FsWatchEnabled      bool
	PluginChecksumsFile string
	PluginDir           string
	ProfilingMode       string
	GracefulExitEnabled bool
	ShowVersion         bool
}

// StartSecretless method is the main entry point into the broker after the CLI
// flags have been parsed
func StartSecretless(params *SecretlessOptions) {
	if params.ShowVersion {
		fmt.Printf("secretless-broker v%s\n", secretless.FullVersionName)
		return
	}

	log.Printf("Secretless v%s starting up...", secretless.FullVersionName)

	// Health check

	util.SetAppInitializedFlag()
	util.SetAppIsLive(false)

	// Construct the deps of Service

	// Coordinates processes interested in exit signals
	exitListener := signal.NewExitListener()

	logger := secretlessLog.New(params.DebugEnabled)

	telemetryProvider, err := telemetry.Init(context.Background())
	if err != nil {
		logger.Errorf("Failed to initialize OpenTelemetry (continuing with telemetry disabled): %s", err)
	} else if telemetryProvider.Enabled() {
		logger.Infof("OpenTelemetry initialized (%s)", telemetryProvider.Summary())
	}

	availPlugins, err := sharedobj.AllAvailablePlugins(
		params.PluginDir,
		params.PluginChecksumsFile,
		logger,
	)

	if err != nil {
		log.Fatalln(err)
	}

	// Optional Performance Profiling
	handlePerformanceProfiling(params.ProfilingMode, exitListener)

	// Get a channel that notifies on configuration changes
	configChangedChan, err := newConfigChangeChan(
		params.ConfigFile,
		params.ConfigManagerSpec,
		params.FsWatchEnabled,
	)
	if err != nil {
		log.Fatalln(err)
	}

	// Main event callbacks definitions

	var allServices internal.Service

	// Main listener for exit signals
	exitListener.AddHandler(func() {
		exitHandler(allServices, telemetryProvider, params)
	})

	// Main processing loop

	// Listen for and restart on config changes
	go func() {
		// TODO: This loop should probably be cleaned up rather than
		//       rely on os.Exit() to end it.
		for {
			logger.Debug("Waiting for new configuration...")
			cfg := <-configChangedChan

			if allServices != nil {
				err := allServices.Stop()
				if err != nil {
					// We don't expect problems with stopping services to be fatal
					logger.Warnf("Problem stopping all services: %s", err)
				}
			}

			logger.Info("Configuration found. Loading...")
			configEnv := v2.NewConfigEnv(logger, availPlugins)
			var reloadErr error
			allServices, reloadErr = reloadConfig(cfg, configEnv, availPlugins, logger)
			if reloadErr != nil {
				shutdownTelemetry(telemetryProvider)
				log.Fatalln(reloadErr)
			}
		}
	}()

	// Listen() returns a channel that will block until signals are handled.
	<-exitListener.Listen()
	logger.Info("Exiting...")
}

func newConfigChangeChan(
	cfgFile string,
	cfgManagerSpec string,
	fsWatchEnabled bool,
) (<-chan v2.Config, error) {

	// Split the configuration spec string into the manager
	// manager's configuration spec string
	splitCfgSpec := strings.SplitN(cfgManagerSpec, "#", 2)
	cfgManager := splitCfgSpec[0]

	// Only try to extract the spec if it's set
	cfgSpec := ""
	if len(splitCfgSpec) > 1 {
		cfgSpec = splitCfgSpec[1]
	}

	switch cfgManager {
	case "configfile":
		// If the spec is not provided, we depend on configfile argument from CLI
		if cfgSpec == "" {
			cfgSpec = cfgFile
		}

		return configfile.NewConfigChannel(cfgSpec, fsWatchEnabled)
	case "k8s/crd":
		return crd.NewConfigChannel(cfgSpec)
	}

	return nil, fmt.Errorf("'%s' configuration manager not supported", cfgManagerSpec)
}

// handlePerformanceProfiling starts a performance profiling, and sets up an
// os.Signal listener that will automatically call Stop() on the profile
// when an system halt is raised.
func handlePerformanceProfiling(profileType string, exitSignals signal.ExitListener) {
	// No profiling was requested
	if profileType == "" {
		return
	}

	// Start profiling
	perfProfile, err := profile.New(profileType)
	if err != nil {
		log.Fatalln(err)
	}

	exitSignals.AddHandler(func() {
		perfProfile.Stop()
	})

	perfProfile.Start()
}

// reloadConfig is the main service reload callback function.
func reloadConfig(
	cfg v2.Config,
	configEnv v2.ConfigEnv,
	availPlugins plugin.AvailablePlugins,
	logger logapi.Logger) (internal.Service, error) {

	ctx, span := telemetry.Tracer("github.com/cyberark/secretless-broker/pkg/secretless/entrypoint").Start(
		context.Background(),
		"secretless.config.reload",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.Int("secretless.services.count", len(cfg.Services))),
	)
	defer span.End()

	// Health check: Not live
	util.SetAppIsLive(false)

	// Ensure config's requested services can be created.
	err := configEnv.Prepare(cfg)
	if err != nil {
		span.SetStatus(codes.Error, "config prepare failed")
		telemetry.RecordConfigReload(ctx, "error")
		telemetry.EmitEvent(ctx, otellog.SeverityError, "configuration reload failed",
			attribute.String("secretless.stage", "prepare"),
			attribute.Int("secretless.services.count", len(cfg.Services)),
		)
		return nil, fmt.Errorf("cannot create all requested services: %s", err)
	}

	// Start Services
	evtNotifier := eventnotifier.New(nil)
	allServices := proxyservice.NewProxyServices(cfg, availPlugins, logger, evtNotifier)
	err = allServices.Start()
	if err != nil {
		span.SetStatus(codes.Error, "services start failed")
		telemetry.RecordConfigReload(ctx, "error")
		telemetry.EmitEvent(ctx, otellog.SeverityError, "configuration reload failed",
			attribute.String("secretless.stage", "start"),
			attribute.Int("secretless.services.count", len(cfg.Services)),
		)
		return nil, fmt.Errorf("Failed to start services: %s", err)
	}

	telemetry.RecordConfigReload(ctx, "ok")
	telemetry.EmitEvent(ctx, otellog.SeverityInfo, "configuration reloaded",
		attribute.Int("secretless.services.count", len(cfg.Services)),
	)

	// Health check: Live
	util.SetAppIsLive(true)

	return allServices, nil
}

func shutdownTelemetry(telemetryProvider *telemetry.Provider) {
	if telemetryProvider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
	defer cancel()
	if err := telemetryProvider.Shutdown(ctx); err != nil {
		log.Printf("Problem shutting down OpenTelemetry: %s", err)
	}
}

func exitHandler(allServices internal.Service, telemetryProvider *telemetry.Provider, params *SecretlessOptions) {
	fmt.Println("Received a stop signal")

	osExit := func(code int) {
		if params.GracefulExitEnabled {
			fmt.Println("Graceful exit enabled, skipping forceful exit")
		} else {
			os.Exit(code)
		}
	}

	if allServices != nil {
		err := allServices.Stop()
		if err != nil {
			// Log but allow cleanup of other subscribers to continue.
			log.Println(err)
		}
	}

	shutdownTelemetry(telemetryProvider)

	// TODO: Ideally we would soft-close all goroutines rather than rely on the
	//       heavy-handed os.Exit to exit the broker when we want to.
	osExit(0)
}
