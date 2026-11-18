package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Finding struct {
	Module   string `json:"module"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	Status   string `json:"status"`
	Evidence string `json:"evidence,omitempty"`
	Detail   string `json:"detail,omitempty"`
}
type Report struct {
	Schema       int       `json:"schema"`
	Generated    string    `json:"generated"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Kernel       string    `json:"kernel"`
	Architecture string    `json:"architecture"`
	Hypervisor   string    `json:"hypervisor"`
	Confidence   int       `json:"confidence"`
	Findings     []Finding `json:"findings"`
}
type Inspector struct {
	root     string
	findings []Finding
	evidence map[string]int
}

func (i *Inspector) path(p string) string {
	return filepath.Join(i.root, strings.TrimPrefix(filepath.Clean(p), "/"))
}
func (i *Inspector) read(p string) (string, error) {
	b, e := os.ReadFile(i.path(p))
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(b)), nil
}
func (i *Inspector) add(m, k, v, status, path, detail string) {
	i.findings = append(i.findings, Finding{m, k, v, status, path, detail})
}
func (i *Inspector) file(m, k, p string) string {
	v, e := i.read(p)
	if e != nil {
		i.add(m, k, "unavailable", "unknown", p, e.Error())
		return ""
	}
	i.add(m, k, v, "observed", p, "")
	return v
}
func (i *Inspector) dir(p string) []os.DirEntry {
	d, e := os.ReadDir(i.path(p))
	if e != nil {
		return nil
	}
	return d
}
func (i *Inspector) score(name string, weight int) { i.evidence[name] += weight }
func (i *Inspector) cpu() {
	m := "cpu"
	raw, e := i.read("/proc/cpuinfo")
	if e != nil {
		i.add(m, "cpuinfo", "unavailable", "unknown", "/proc/cpuinfo", e.Error())
		return
	}
	blocks := strings.Split(raw, "\n\n")
	cores := 0
	flags := map[string]bool{}
	vendors := map[string]bool{}
	models := map[string]bool{}
	for _, b := range blocks {
		if strings.TrimSpace(b) == "" {
			continue
		}
		cores++
		for _, line := range strings.Split(b, "\n") {
			p := strings.SplitN(line, ":", 2)
			if len(p) != 2 {
				continue
			}
			key := strings.TrimSpace(p[0])
			val := strings.TrimSpace(p[1])
			switch key {
			case "flags", "Features":
				for _, f := range strings.Fields(val) {
					flags[f] = true
				}
			case "vendor_id":
				vendors[val] = true
			case "model name":
				models[val] = true
			}
		}
	}
	i.add(m, "logical_cpus", strconv.Itoa(cores), "observed", "/proc/cpuinfo", "Visible logical processors")
	i.add(m, "go_arch", runtime.GOARCH, "observed", "runtime.GOARCH", "")
	i.add(m, "cpu_vendors", strings.Join(sortedKeys(vendors), ", "), "observed", "/proc/cpuinfo", "")
	i.add(m, "models", strings.Join(sortedKeys(models), " | "), "observed", "/proc/cpuinfo", "")
	for _, f := range []string{"hypervisor", "vmx", "svm", "tsc", "constant_tsc", "nonstop_tsc", "invtsc", "tsc_deadline_timer", "x2apic", "pcid", "aes", "rdrand", "rdseed"} {
		status := "absent"
		if flags[f] {
			status = "present"
		}
		i.add(m, "flag."+f, status, "observed", "/proc/cpuinfo", "")
	}
	if flags["hypervisor"] {
		i.score("generic", 20)
	}
	for _, p := range []string{"/sys/devices/system/cpu/online", "/sys/devices/system/cpu/possible", "/sys/devices/system/cpu/present", "/sys/devices/system/cpu/smt/active", "/sys/devices/system/cpu/vulnerabilities/spectre_v2"} {
		i.file(m, filepath.Base(p), p)
	}
}
func sortedKeys(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
func (i *Inspector) identity() {
	m := "identity"
	for _, kv := range [][2]string{{"sys_vendor", "/sys/class/dmi/id/sys_vendor"}, {"product_name", "/sys/class/dmi/id/product_name"}, {"product_version", "/sys/class/dmi/id/product_version"}, {"board_vendor", "/sys/class/dmi/id/board_vendor"}, {"bios_vendor", "/sys/class/dmi/id/bios_vendor"}, {"chassis_type", "/sys/class/dmi/id/chassis_type"}} {
		v := i.file(m, kv[0], kv[1])
		l := strings.ToLower(v)
		switch {
		case strings.Contains(l, "qemu"), strings.Contains(l, "kvm"), strings.Contains(l, "bochs"):
			i.score("KVM/QEMU", 25)
		case strings.Contains(l, "vmware"):
			i.score("VMware", 25)
		case strings.Contains(l, "virtualbox"), strings.Contains(l, "innotek"):
			i.score("VirtualBox", 25)
		case strings.Contains(l, "microsoft corporation"), strings.Contains(l, "virtual machine"):
			i.score("Hyper-V", 20)
		case strings.Contains(l, "xen"):
			i.score("Xen", 25)
		case strings.Contains(l, "bhyve"):
			i.score("bhyve", 25)
		case strings.Contains(l, "parallels"):
			i.score("Parallels", 25)
		}
	}
	if v, e := i.read("/sys/hypervisor/type"); e == nil {
		i.add(m, "sys_hypervisor", v, "observed", "/sys/hypervisor/type", "")
		if strings.Contains(strings.ToLower(v), "xen") {
			i.score("Xen", 50)
		}
	} else {
		i.add(m, "sys_hypervisor", "unavailable", "unknown", "/sys/hypervisor/type", e.Error())
	}
	if v, e := i.read("/proc/device-tree/hypervisor/compatible"); e == nil {
		i.add(m, "device_tree_hypervisor", strings.ReplaceAll(v, "\x00", ","), "observed", "/proc/device-tree/hypervisor/compatible", "")
	}
}
func (i *Inspector) virtio() {
	m := "virtio"
	dirs := i.dir("/sys/bus/virtio/devices")
	if dirs == nil {
		i.add(m, "devices", "unavailable or empty", "unknown", "/sys/bus/virtio/devices", "")
	} else {
		i.add(m, "count", strconv.Itoa(len(dirs)), "observed", "/sys/bus/virtio/devices", "")
	}
	for _, d := range dirs {
		name := d.Name()
		base := "/sys/bus/virtio/devices/" + name
		dev, _ := i.read(base + "/device")
		vendor, _ := i.read(base + "/vendor")
		driver := "unbound"
		if l, e := os.Readlink(i.path(base + "/driver")); e == nil {
			driver = filepath.Base(l)
		}
		i.add(m, name, fmt.Sprintf("device=%s vendor=%s driver=%s", dev, vendor, driver), "observed", base, "")
		i.score("KVM/QEMU", 5)
	}
	for _, mod := range []string{"virtio_pci", "virtio_net", "virtio_blk", "virtio_scsi", "virtio_balloon", "virtio_rng", "virtio_console", "virtio_gpu", "vmw_balloon", "hv_vmbus", "xen_netfront", "vboxguest"} {
		if _, e := os.Stat(i.path("/sys/module/" + mod)); e == nil {
			i.add(m, "module."+mod, "loaded", "observed", "/sys/module/"+mod, "")
			switch {
			case strings.HasPrefix(mod, "virtio_"):
				i.score("KVM/QEMU", 2)
			case strings.HasPrefix(mod, "hv_"):
				i.score("Hyper-V", 15)
			case strings.HasPrefix(mod, "xen_"):
				i.score("Xen", 15)
			case strings.HasPrefix(mod, "vbox"):
				i.score("VirtualBox", 15)
			case strings.HasPrefix(mod, "vmw_"):
				i.score("VMware", 15)
			}
		}
	}
}
func (i *Inspector) clock() {
	m := "clock"
	for _, p := range []string{"/sys/devices/system/clocksource/clocksource0/current_clocksource", "/sys/devices/system/clocksource/clocksource0/available_clocksource", "/proc/uptime", "/proc/driver/rtc"} {
		v := i.file(m, filepath.Base(p), p)
		if strings.Contains(v, "kvm-clock") {
			i.score("KVM/QEMU", 35)
		}
		if strings.Contains(v, "hyperv_clocksource") {
			i.score("Hyper-V", 35)
		}
		if strings.Contains(v, "xen") {
			i.score("Xen", 30)
		}
	}
}
func (i *Inspector) storage() {
	m := "storage"
	dirs := i.dir("/sys/block")
	if dirs == nil {
		i.add(m, "block", "unavailable", "unknown", "/sys/block", "")
		return
	}
	for _, d := range dirs {
		name := d.Name()
		base := "/sys/block/" + name
		vals := []string{}
		for _, p := range []string{"device/model", "device/vendor", "queue/rotational", "queue/scheduler", "queue/logical_block_size", "size"} {
			v, e := i.read(base + "/" + p)
			if e == nil {
				vals = append(vals, p+"="+v)
			}
		}
		if l, e := os.Readlink(i.path(base + "/device/driver")); e == nil {
			vals = append(vals, "driver="+filepath.Base(l))
		}
		i.add(m, name, strings.Join(vals, "; "), "observed", base, "")
		if strings.HasPrefix(name, "vd") {
			i.score("KVM/QEMU", 5)
		}
	}
}
func (i *Inspector) network() {
	m := "network"
	for _, d := range i.dir("/sys/class/net") {
		name := d.Name()
		base := "/sys/class/net/" + name
		vals := []string{}
		for _, p := range []string{"address", "type", "mtu", "operstate", "device/vendor", "device/device", "device/numa_node", "queues"} {
			if p == "queues" {
				if q := i.dir(base + "/queues"); q != nil {
					vals = append(vals, fmt.Sprintf("queues=%d", len(q)))
				}
				continue
			}
			if v, e := i.read(base + "/" + p); e == nil {
				vals = append(vals, p+"="+v)
			}
		}
		if l, e := os.Readlink(i.path(base + "/device/driver")); e == nil {
			driver := filepath.Base(l)
			vals = append(vals, "driver="+driver)
			if driver == "virtio_net" {
				i.score("KVM/QEMU", 15)
			}
			if driver == "vmxnet3" {
				i.score("VMware", 30)
			}
			if driver == "hv_netvsc" {
				i.score("Hyper-V", 30)
			}
		}
		i.add(m, name, strings.Join(vals, "; "), "observed", base, "")
	}
}
func (i *Inspector) memory() {
	m := "memory"
	for _, p := range []string{"/sys/devices/system/memory/block_size_bytes", "/sys/kernel/mm/transparent_hugepage/enabled", "/proc/meminfo"} {
		v, e := i.read(p)
		if e != nil {
			i.add(m, filepath.Base(p), "unavailable", "unknown", p, e.Error())
			continue
		}
		if strings.HasSuffix(p, "meminfo") {
			for _, line := range strings.Split(v, "\n") {
				if strings.HasPrefix(line, "MemTotal:") || strings.HasPrefix(line, "HugePages_Total:") || strings.HasPrefix(line, "Hugepagesize:") {
					i.add(m, strings.TrimSuffix(strings.Fields(line)[0], ":"), strings.TrimSpace(strings.TrimPrefix(line, strings.Fields(line)[0])), "observed", p, "")
				}
			}
		} else {
			i.add(m, filepath.Base(p), v, "observed", p, "")
		}
	}
	for _, p := range []string{"/sys/devices/virtual/misc/virtio-ports", "/sys/devices/system/node"} {
		if d := i.dir(p); d != nil {
			i.add(m, filepath.Base(p), fmt.Sprintf("entries=%d", len(d)), "observed", p, "")
		}
	}
}
func (i *Inspector) security() {
	m := "security"
	for _, p := range []string{"/sys/kernel/security/lockdown", "/sys/kernel/security/lsm", "/sys/kernel/mm/ksm/run", "/sys/kernel/mm/transparent_hugepage/enabled", "/sys/module/kvm_intel/parameters/nested", "/sys/module/kvm_amd/parameters/nested", "/sys/firmware/efi/fw_platform_size", "/sys/devices/system/cpu/vulnerabilities/meltdown"} {
		i.file(m, filepath.Base(p), p)
	}
	for _, p := range []string{"/sys/firmware/tdx", "/sys/kernel/config/tsm", "/sys/firmware/sev", "/dev/sev-guest", "/dev/tdx-guest", "/dev/virtio-ports/org.qemu.guest_agent.0"} {
		_, e := os.Stat(i.path(p))
		status := "not exposed"
		if e == nil {
			status = "present"
		}
		i.add(m, p, status, "observed", p, "Presence alone does not establish confidential guest security")
	}
}
func (i *Inspector) integration() {
	m := "integration"
	for _, name := range []string{"qemu-guest-agent", "spice-vdagentd", "vmtoolsd", "VBoxService", "systemd-timesyncd"} {
		if i.root != "/" {
			i.add(m, name, "not probed in offline root", "unknown", "systemctl", "")
			continue
		}
		ctx, e := exec.Command("systemctl", "is-active", name+".service").CombinedOutput()
		if e != nil {
			i.add(m, name, strings.TrimSpace(string(ctx)), "observed", "systemctl is-active", "")
		} else {
			i.add(m, name, strings.TrimSpace(string(ctx)), "observed", "systemctl is-active", "")
		}
	}
	for _, p := range []string{"/dev/virtio-ports/org.qemu.guest_agent.0", "/dev/vport0p1", "/run/systemd/container"} {
		if v, e := i.read(p); e == nil {
			i.add(m, p, v, "observed", p, "")
		} else if _, e := os.Stat(i.path(p)); e == nil {
			i.add(m, p, "present", "observed", p, "")
		}
	}
}
func (i *Inspector) summary() (string, int) {
	winner := "undetermined"
	score := 0
	second := 0
	for name, n := range i.evidence {
		if name == "generic" {
			continue
		}
		if n > score {
			second = score
			score = n
			winner = name
		} else if n > second {
			second = n
		}
	}
	if score == 0 {
		return winner, 0
	}
	confidence := score
	if confidence > 95 {
		confidence = 95
	}
	if score-second < 15 && second > 0 {
		confidence -= 20
	}
	if confidence < 5 {
		confidence = 5
	}
	return winner, confidence
}
func inspect(root string, modules map[string]bool) Report {
	i := &Inspector{root: root, evidence: map[string]int{}}
	calls := []struct {
		name string
		fn   func()
	}{{"identity", i.identity}, {"cpu", i.cpu}, {"virtio", i.virtio}, {"clock", i.clock}, {"storage", i.storage}, {"network", i.network}, {"memory", i.memory}, {"security", i.security}, {"integration", i.integration}}
	for _, c := range calls {
		if modules["all"] || modules[c.name] {
			c.fn()
		}
	}
	h, _ := os.Hostname()
	osname := "Linux"
	if v, e := i.read("/etc/os-release"); e == nil {
		for _, line := range strings.Split(v, "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osname = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	kernel, _ := i.read("/proc/sys/kernel/osrelease")
	hyp, conf := i.summary()
	return Report{1, time.Now().UTC().Format(time.RFC3339), h, osname, kernel, runtime.GOARCH, hyp, conf, i.findings}
}
func writeJSON(path string, r any) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if path == "-" {
		_, e = os.Stdout.Write(b)
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func writeCSV(path string, r Report) error {
	var w *csv.Writer
	var f *os.File
	if path == "-" {
		w = csv.NewWriter(os.Stdout)
	} else {
		var e error
		f, e = os.Create(path)
		if e != nil {
			return e
		}
		defer f.Close()
		w = csv.NewWriter(f)
	}
	w.Write([]string{"module", "key", "value", "status", "evidence", "detail"})
	for _, v := range r.Findings {
		w.Write([]string{v.Module, v.Key, v.Value, v.Status, v.Evidence, v.Detail})
	}
	w.Flush()
	return w.Error()
}
func hash(f Finding) string {
	b, _ := json.Marshal([]string{f.Module, f.Key, f.Value, f.Status})
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}
func compare(a, b Report) []string {
	left := map[string]Finding{}
	right := map[string]Finding{}
	for _, f := range a.Findings {
		left[f.Module+"/"+f.Key] = f
	}
	for _, f := range b.Findings {
		right[f.Module+"/"+f.Key] = f
	}
	keys := map[string]bool{}
	for k := range left {
		keys[k] = true
	}
	for k := range right {
		keys[k] = true
	}
	names := sortedKeys(keys)
	var changes []string
	for _, k := range names {
		x, okx := left[k]
		y, oky := right[k]
		switch {
		case !okx:
			changes = append(changes, "+ "+k+": "+y.Value)
		case !oky:
			changes = append(changes, "- "+k+": "+x.Value)
		case hash(x) != hash(y):
			changes = append(changes, "~ "+k+": "+x.Value+" => "+y.Value)
		}
	}
	return changes
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func color(s, code string, on bool) string {
	if !on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func display(r Report, on bool, filter string) {
	fmt.Println(color("VIRTUALIZATION FINGERPRINT", "1;38;2;100;220;255", on))
	fmt.Printf("Host: %s   OS: %s   Kernel: %s\n", r.Hostname, r.OS, r.Kernel)
	fmt.Printf("Hypervisor evidence: %s   confidence heuristic: %d/95\n", color(r.Hypervisor, "1;36", on), r.Confidence)
	fmt.Println("Confidence is a heuristic, not a calibrated probability. Missing evidence is not proof of bare metal.")
	current := ""
	for _, f := range r.Findings {
		if filter != "all" && f.Module != filter {
			continue
		}
		if current != f.Module {
			current = f.Module
			fmt.Println("\n" + color(strings.ToUpper(current), "1;38;2;210;155;255", on))
		}
		v := strings.ReplaceAll(f.Value, "\n", " | ")
		if len(v) > 230 {
			v = v[:230] + "..."
		}
		fmt.Printf("  %-29s %s\n", f.Key, color(v, "38;2;175;225;185", on))
	}
}
func usage() {
	fmt.Println("virtualization-fingerprint [inspect|cpu|virtio|clock|storage|network|memory|security|identity|integration|report|compare] [flags]")
	fmt.Println("  -root PATH      inspect a mounted filesystem tree (offline; no host commands)")
	fmt.Println("  -format text|json|csv    report output format")
	fmt.Println("  -output PATH    output path for report; - means stdout")
	fmt.Println("  -no-color       disable ANSI colors")
	fmt.Println("  -before PATH -after PATH    compare saved JSON reports")
	fmt.Println("  -help           show usage")
}
func run() error {
	args := os.Args[1:]
	cmd := "inspect"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	root := fs.String("root", "/", "filesystem root")
	format := fs.String("format", "text", "text, json, csv")
	output := fs.String("output", "-", "output path")
	noColor := fs.Bool("no-color", false, "disable color")
	before := fs.String("before", "", "old report")
	after := fs.String("after", "", "new report")
	help := fs.Bool("help", false, "help")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *help {
		usage()
		return nil
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	if cmd == "compare" {
		if *before == "" || *after == "" {
			return errors.New("compare requires -before and -after")
		}
		var a, b Report
		for _, p := range []struct {
			path string
			dest *Report
		}{{*before, &a}, {*after, &b}} {
			raw, e := os.ReadFile(p.path)
			if e != nil {
				return e
			}
			if e = json.Unmarshal(raw, p.dest); e != nil {
				return e
			}
		}
		if a.Schema != 1 || b.Schema != 1 {
			return errors.New("unsupported report schema")
		}
		changes := compare(a, b)
		if len(changes) == 0 {
			fmt.Println("No changes detected")
		} else {
			for _, v := range changes {
				fmt.Println(v)
			}
		}
		return nil
	}
	valid := map[string]bool{"inspect": true, "report": true, "identity": true, "cpu": true, "virtio": true, "clock": true, "storage": true, "network": true, "memory": true, "security": true, "integration": true}
	if !valid[cmd] {
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	if *format != "text" && *format != "json" && *format != "csv" {
		return errors.New("format must be text, json, or csv")
	}
	if st, e := os.Stat(*root); e != nil || !st.IsDir() {
		return errors.New("root must be an accessible directory")
	}
	mods := map[string]bool{cmd: true}
	if cmd == "inspect" || cmd == "report" {
		mods = map[string]bool{"all": true}
	}
	r := inspect(*root, mods)
	switch *format {
	case "json":
		return writeJSON(*output, r)
	case "csv":
		return writeCSV(*output, r)
	default:
		if *output != "-" {
			return errors.New("text output supports stdout only; use -format json or csv for files")
		}
		display(r, !(*noColor) || false, func() string {
			if mods["all"] {
				return "all"
			}
			return cmd
		}())
		return nil
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "virtualization-fingerprint:", ansi.ReplaceAllString(e.Error(), ""))
		os.Exit(1)
	}
}
