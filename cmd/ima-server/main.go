// Command ima-server runs go-ima in standalone mode: the /v1 REST API over a
// PostgreSQL database it owns. Infrastructure lifecycle comes from go-base.
//
//	ima-server -config config/ima-server.conf -migrate   # apply schema, then exit
//	ima-server -config config/ima-server.conf            # serve
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	base "github.com/ninepeach/go-base/core"
	"github.com/ninepeach/go-base/postgres"
	ima "github.com/ninepeach/go-ima"
	imapg "github.com/ninepeach/go-ima/storage/postgres"
	imahttp "github.com/ninepeach/go-ima/transport/http"
)

// serverConfig is the `server` section. Durations are Go duration strings.
type serverConfig struct {
	Listen            string   `conf:"listen"`
	ReadHeaderTimeout string   `conf:"read_header_timeout"`
	ShutdownTimeout   string   `conf:"shutdown_timeout"`
	TrustedProxies    []string `conf:"trusted_proxies"`
}

// imaConfig is the `ima` section.
type imaConfig struct {
	AccessTTL     string `conf:"access_ttl"`
	RefreshTTL    string `conf:"refresh_ttl"`
	SessionMaxAge string `conf:"session_max_age"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ima-server:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config/ima-server.conf", "path to the .conf file")
	migrate := flag.Bool("migrate", false, "apply database migrations and exit")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt, err := base.New(ctx, base.WithConfig(*configPath), base.Use(postgres.Register("primary")))
	if err != nil {
		return err
	}
	srvCfg, err := decodeServer(rt.Config())
	if err != nil {
		closeRuntime(rt, 10*time.Second)
		return err
	}
	shutdown := srvCfg.shutdown
	defer closeRuntime(rt, shutdown)
	log := rt.Logger()
	pool := postgres.From(rt, "primary")

	if *migrate {
		if err := imapg.Migrate(ctx, pool); err != nil {
			return err
		}
		v, err := imapg.CurrentVersion(ctx, pool)
		if err != nil {
			return err
		}
		log.Info("migrations applied", "version", v)
		return nil
	}
	if _, err := imapg.CheckSchema(ctx, pool); err != nil {
		return err
	}

	store, err := imapg.New(pool)
	if err != nil {
		return err
	}
	opts := ima.Options{Repositories: store.Repositories(), Logger: log.With("component", "ima")}
	if err := decodeIMA(rt.Config(), &opts); err != nil {
		return err
	}
	if opts.Limiter == nil {
		log.Warn("no rate limiter configured; login and registration are not throttled")
	}
	svc, err := ima.New(opts)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", imahttp.New(svc, imahttp.Options{TrustedProxies: srvCfg.trusted, Logger: log}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		hctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if rep := rt.Health(hctx); !rep.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              srvCfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: srvCfg.readHeader,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srvCfg.listen)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	// Stop intake and drain in-flight requests before infrastructure closes.
	sctx, cancel := context.WithTimeout(context.Background(), shutdown)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	return nil
}

func closeRuntime(rt *base.Runtime, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := rt.Close(ctx); err != nil {
		rt.Logger().Error("infrastructure shutdown failed", "error", err)
	}
}

type resolvedServer struct {
	listen     string
	readHeader time.Duration
	shutdown   time.Duration
	trusted    []netip.Prefix
}

func decodeServer(cfg base.Config) (resolvedServer, error) {
	sc := serverConfig{Listen: ":8080", ReadHeaderTimeout: "5s", ShutdownTimeout: "15s"}
	if err := cfg.Decode("server", &sc); err != nil && !errors.Is(err, base.ErrConfigNotFound) {
		return resolvedServer{}, fmt.Errorf("config server: %w", err)
	}
	out := resolvedServer{listen: sc.Listen}
	var err error
	if out.readHeader, err = parseDuration("server.read_header_timeout", sc.ReadHeaderTimeout); err != nil {
		return out, err
	}
	if out.shutdown, err = parseDuration("server.shutdown_timeout", sc.ShutdownTimeout); err != nil {
		return out, err
	}
	for _, p := range sc.TrustedProxies {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return out, fmt.Errorf("config server.trusted_proxies: invalid entry")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		out.trusted = append(out.trusted, prefix.Masked())
	}
	return out, nil
}

func decodeIMA(cfg base.Config, opts *ima.Options) error {
	var ic imaConfig
	if err := cfg.Decode("ima", &ic); err != nil {
		if errors.Is(err, base.ErrConfigNotFound) {
			return nil
		}
		return fmt.Errorf("config ima: %w", err)
	}
	for _, f := range []struct {
		name string
		src  string
		dst  *time.Duration
	}{
		{"ima.access_ttl", ic.AccessTTL, &opts.AccessTTL},
		{"ima.refresh_ttl", ic.RefreshTTL, &opts.RefreshTTL},
		{"ima.session_max_age", ic.SessionMaxAge, &opts.SessionMaxAge},
	} {
		if f.src == "" {
			continue
		}
		d, err := parseDuration(f.name, f.src)
		if err != nil {
			return err
		}
		*f.dst = d
	}
	return nil
}

func parseDuration(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config %s: must be a positive duration", name)
	}
	return d, nil
}
