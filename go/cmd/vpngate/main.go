package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"vpngate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "harvest":
		return runHarvest(args[1:], stdout, stderr)
	case "generate":
		return runGenerate(args[1:], stdout, stderr)
	case "probe":
		return runProbe(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "decode":
		return runDecode(args[1:], stdout, stderr)
	case "version":
		if len(args) != 1 {
			return usageError(stderr, "version: unexpected arguments")
		}
		fmt.Fprintln(stdout, "vpngate "+vpngate.Version)
		return 0
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "vpngate: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage:
  vpngate harvest   [--source plugin|csv|both] [--polls N] [--interval SEC]
                    [--timeout SEC] [--out FILE] [--state FILE]
  vpngate generate  [--in FILE] [--batch N] [--base-port N] [--out DIR] [--certs FILE]
  vpngate probe     [--in FILE] [--batch N] [--timeout SEC] [--workers N]
                    [--prefilter] [--out FILE] [--usable FILE] [--certs FILE]
  vpngate export    [--in FILE] [--format json|csv|plain|singbox] [--out FILE] [--certs FILE]
  vpngate decode    --in FILE [--out FILE]
  vpngate version
`)
}

func runDecode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input DAT file")
	out := fs.String("out", "", "output Node JSON file")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if *in == "" {
		return usageError(stderr, "decode: --in is required")
	}
	records, meta, err := vpngate.DecodeDATFile(*in)
	if err != nil {
		return runtimeError(stderr, err)
	}
	nodes := records.Nodes("plugin", 0, 0)
	if err := withOutput(*out, stdout, func(w io.Writer) error {
		return vpngate.WriteNodesJSON(w, nodes)
	}); err != nil {
		return runtimeError(stderr, err)
	}
	fmt.Fprintf(stderr, "salt=%s key=%s hosts=%d columns=%d plaintext=%d\n",
		meta.SaltHex, meta.KeyHex, meta.NumHosts, meta.Columns, meta.PlaintextLen)
	return 0
}

func runHarvest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harvest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "both", "plugin, csv, or both")
	polls := fs.Int("polls", 1, "number of polls")
	interval := fs.Int("interval", 60, "seconds between polls")
	timeout := fs.Int("timeout", 30, "HTTP timeout seconds")
	out := fs.String("out", "", "output Node JSON file")
	state := fs.String("state", "", "state Node JSON file")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if *source != "plugin" && *source != "csv" && *source != "both" {
		return usageError(stderr, "harvest: invalid --source")
	}
	if *polls < 1 || *interval < 0 || *timeout < 1 {
		return usageError(stderr, "harvest: invalid numeric flag")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	timeoutDur := time.Duration(*timeout) * time.Second

	var all []vpngate.Node
	var certs vpngate.CertBundle
	if *state != "" {
		if _, err := os.Stat(*state); err == nil {
			nodes, err := vpngate.LoadNodesFile(*state)
			if err != nil {
				return runtimeError(stderr, fmt.Errorf("state: %w", err))
			}
			all = append(all, nodes...)
		} else if !errors.Is(err, os.ErrNotExist) {
			return runtimeError(stderr, err)
		}
	}

	for poll := 0; poll < *polls; poll++ {
		if poll > 0 {
			timer := time.NewTimer(time.Duration(*interval) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return runtimeError(stderr, ctx.Err())
			case <-timer.C:
			}
		}
		fetched, pollCerts, err := fetchSources(ctx, *source, timeoutDur)
		if err != nil {
			return runtimeError(stderr, err)
		}
		if pollCerts.Complete() {
			certs = pollCerts
		}
		all = vpngate.Merge(append(all, fetched...))
		fmt.Fprintf(stderr, "poll %d/%d: %d nodes\n", poll+1, *polls, len(fetched))
	}

	if *state != "" {
		if err := vpngate.SaveNodesFile(*state, all); err != nil {
			return runtimeError(stderr, fmt.Errorf("state: %w", err))
		}
	}
	if err := withOutput(*out, stdout, func(w io.Writer) error {
		return vpngate.WriteNodesJSON(w, all)
	}); err != nil {
		return runtimeError(stderr, err)
	}
	if certs.Complete() {
		target := *out
		if target == "" {
			target = *state
		}
		if target != "" {
			if err := vpngate.SaveCertsFile(target+".certs.json", certs); err != nil {
				return runtimeError(stderr, fmt.Errorf("certs: %w", err))
			}
		}
	}
	fmt.Fprintf(stderr, "harvested %d nodes\n", len(all))
	return 0
}

func fetchSources(ctx context.Context, source string, timeout time.Duration) ([]vpngate.Node, vpngate.CertBundle, error) {
	var nodes []vpngate.Node
	var certs vpngate.CertBundle
	var errs []string
	okSources := 0
	if source == "plugin" || source == "both" {
		src := &vpngate.PluginSource{Timeout: timeout}
		got, err := src.Fetch(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			okSources++
			nodes = append(nodes, got...)
		}
	}
	if source == "csv" || source == "both" {
		src := &vpngate.CSVSource{Timeout: timeout}
		got, err := src.Fetch(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			okSources++
			nodes = append(nodes, got...)
			if src.Certificates.Complete() {
				certs = src.Certificates
			}
		}
	}
	if okSources == 0 && len(errs) > 0 {
		return nil, certs, fmt.Errorf("all sources failed: %s", strings.Join(errs, "; "))
	}
	return nodes, certs, nil
}

func runGenerate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input Node JSON file (default stdin)")
	batch := fs.Int("batch", 32, "nodes per config")
	basePort := fs.Int("base-port", 20000, "first inbound port")
	outDir := fs.String("out", "singbox", "output directory")
	certsFile := fs.String("certs", "", "certificate JSON file")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if *batch < 1 || *basePort < 1 || *basePort > 65535 {
		return usageError(stderr, "generate: invalid --batch or --base-port")
	}
	if *outDir == "" {
		return usageError(stderr, "generate: --out is required")
	}
	nodes, _, isResults, err := loadInput(*in, os.Stdin)
	if err != nil {
		return runtimeError(stderr, err)
	}
	if isResults {
		return runtimeError(stderr, errors.New("generate: input must be a Node array"))
	}
	nodes = filterUsableNodes(nodes)
	if len(nodes) == 0 {
		return runtimeError(stderr, errors.New("generate: no nodes with ssl_ports"))
	}
	certs, err := resolveCerts(*certsFile, *in, 30*time.Second)
	if err != nil {
		return runtimeError(stderr, err)
	}
	paths, err := vpngate.WriteBatchConfigs(nodes, certs, *basePort, *batch, *outDir)
	if err != nil {
		return runtimeError(stderr, err)
	}
	fmt.Fprintf(stderr, "wrote %d config(s) with %d nodes\n", len(paths), len(nodes))
	return 0
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input Node JSON file (default stdin)")
	batch := fs.Int("batch", 32, "nodes per sing-box process")
	basePort := fs.Int("base-port", 20000, "first inbound port")
	timeout := fs.Int("timeout", 12, "probe timeout seconds")
	workers := fs.Int("workers", 0, "concurrent probes (default min(batch,32))")
	prefilter := fs.Bool("prefilter", false, "TCP prefilter before sing-box")
	out := fs.String("out", "", "result JSON file")
	usable := fs.String("usable", "", "usable Node JSON file")
	certsFile := fs.String("certs", "", "certificate JSON file")
	singboxBin := fs.String("singbox", "", "sing-box binary path (default: lookup in PATH)")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if *batch < 1 || *timeout < 1 || *workers < 0 || *basePort < 1 || *basePort > 65535 {
		return usageError(stderr, "probe: invalid numeric flag")
	}
	nodes, _, isResults, err := loadInput(*in, os.Stdin)
	if err != nil {
		return runtimeError(stderr, err)
	}
	if isResults {
		return runtimeError(stderr, errors.New("probe: input must be a Node array"))
	}
	hasTargets := false
	for _, n := range nodes {
		if len(n.SSLPorts) > 0 {
			hasTargets = true
			break
		}
	}
	var certs vpngate.CertBundle
	if hasTargets {
		certs, err = resolveCerts(*certsFile, *in, 30*time.Second)
		if err != nil {
			return runtimeError(stderr, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	prober := &vpngate.SingBoxBatchProber{
		Binary:       resolveSingBox(*singboxBin),
		Certificates: certs,
		BatchSize:    *batch,
		BasePort:     *basePort,
		ProbeTimeout: time.Duration(*timeout) * time.Second,
		Workers:      *workers,
	}
	if *prefilter {
		prober.PreFilter = &vpngate.TCPPreFilter{Timeout: 3 * time.Second}
	}
	results, probeErr := prober.Probe(ctx, nodes)
	if probeErr != nil {
		fmt.Fprintf(stderr, "vpngate: probe: %v\n", probeErr)
	}
	if err := withOutput(*out, stdout, func(w io.Writer) error {
		return vpngate.WriteResultsJSON(w, results)
	}); err != nil {
		return runtimeError(stderr, err)
	}
	if *usable != "" {
		usableNodes := make([]vpngate.Node, 0, len(results))
		for i, r := range results {
			if !r.OK || i >= len(nodes) {
				continue
			}
			n := nodes[i]
			n.SSLPorts = []int{r.Port}
			usableNodes = append(usableNodes, n)
		}
		if err := vpngate.SaveNodesFile(*usable, usableNodes); err != nil {
			return runtimeError(stderr, err)
		}
	}
	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
		}
	}
	fmt.Fprintf(stderr, "probed %d: ok %d\n", len(results), okCount)
	if probeErr != nil {
		return 1
	}
	return 0
}

func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input JSON file (default stdin)")
	format := fs.String("format", "json", "json, csv, plain, or singbox")
	out := fs.String("out", "", "output file")
	certsFile := fs.String("certs", "", "certificate JSON file (singbox only)")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	nodes, results, isResults, err := loadInput(*in, os.Stdin)
	if err != nil {
		return runtimeError(stderr, err)
	}

	var exporter vpngate.Exporter
	switch *format {
	case "json":
		exporter = vpngate.JSONExporter{}
	case "csv":
		exporter = vpngate.CSVExporter{}
	case "plain":
		exporter = vpngate.PlainExporter{}
	case "singbox":
		certs, err := resolveCerts(*certsFile, *in, 30*time.Second)
		if err != nil {
			return runtimeError(stderr, err)
		}
		exporter = vpngate.SingBoxExporter{Certificates: certs}
	default:
		return usageError(stderr, "export: invalid --format")
	}

	err = withOutput(*out, stdout, func(w io.Writer) error {
		if isResults {
			if re, ok := exporter.(vpngate.ResultExporter); ok {
				return re.ExportResults(w, results)
			}
			switch exporter.Format() {
			case "plain":
				for _, r := range results {
					if r.OK {
						if _, err := fmt.Fprintf(w, "%s:%d\n", r.IP, r.Port); err != nil {
							return err
						}
					}
				}
				return nil
			default:
				return exporter.Export(w, vpngate.ResultsToNodes(results))
			}
		}
		return exporter.Export(w, nodes)
	})
	if err != nil {
		return runtimeError(stderr, err)
	}
	return 0
}

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "vpngate: unexpected argument %q\n", fs.Arg(0))
		return 2, false
	}
	return 0, true
}

func usageError(stderr io.Writer, msg string) int {
	fmt.Fprintln(stderr, "vpngate: "+msg)
	return 2
}

func runtimeError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "vpngate: %v\n", err)
	return 1
}

func withOutput(path string, stdout io.Writer, fn func(io.Writer) error) error {
	if path == "" {
		return fn(stdout)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadInput(path string, stdin io.Reader) ([]vpngate.Node, []vpngate.Result, bool, error) {
	var data []byte
	var err error
	if path == "" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, nil, false, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, false, errors.New("empty input")
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, nil, false, fmt.Errorf("input is not a JSON array: %w", err)
	}
	isResults := false
	if len(raws) > 0 {
		var probe struct {
			OK *bool `json:"ok"`
		}
		if err := json.Unmarshal(raws[0], &probe); err == nil && probe.OK != nil {
			isResults = true
		}
	}
	if isResults {
		results, err := vpngate.ReadResults(bytes.NewReader(data))
		return nil, results, true, err
	}
	nodes, err := vpngate.ReadNodes(bytes.NewReader(data))
	return nodes, nil, false, err
}

func resolveSingBox(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("VPNGATE_SING_BOX"); env != "" {
		return env
	}
	return ""
}

func resolveCerts(explicit, inPath string, timeout time.Duration) (vpngate.CertBundle, error) {
	if explicit != "" {
		certs, err := vpngate.LoadCertsFile(explicit)
		if err != nil {
			return vpngate.CertBundle{}, fmt.Errorf("certs: %w", err)
		}
		if !certs.Complete() {
			return vpngate.CertBundle{}, errors.New("certs: ca/cert/key are incomplete")
		}
		return certs, nil
	}
	var candidates []string
	if inPath != "" {
		candidates = append(candidates, inPath+".certs.json")
		candidates = append(candidates, filepath.Join(filepath.Dir(inPath), "certs.json"))
	} else {
		candidates = append(candidates, "certs.json")
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return vpngate.CertBundle{}, err
		}
		certs, err := vpngate.LoadCertsFile(path)
		if err != nil {
			return vpngate.CertBundle{}, fmt.Errorf("certs %s: %w", path, err)
		}
		if !certs.Complete() {
			return vpngate.CertBundle{}, fmt.Errorf("certs %s: ca/cert/key are incomplete", path)
		}
		return certs, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	src := &vpngate.CSVSource{Timeout: timeout}
	if _, err := src.Fetch(ctx); err != nil {
		return vpngate.CertBundle{}, fmt.Errorf("certs: %w", err)
	}
	if !src.Certificates.Complete() {
		return vpngate.CertBundle{}, errors.New("certs: public CSV has no complete ca/cert/key")
	}
	return src.Certificates, nil
}

func filterUsableNodes(nodes []vpngate.Node) []vpngate.Node {
	out := make([]vpngate.Node, 0, len(nodes))
	for _, n := range nodes {
		if len(n.SSLPorts) > 0 {
			out = append(out, n)
		}
	}
	return out
}
