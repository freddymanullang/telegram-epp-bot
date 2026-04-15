set -e

BASE_DIR=/home/leenux/telegram-epp-bot

rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR/cmd/bot"
mkdir -p "$BASE_DIR/internal/app"
mkdir -p "$BASE_DIR/internal/audit"
mkdir -p "$BASE_DIR/internal/bot"
mkdir -p "$BASE_DIR/internal/config"
mkdir -p "$BASE_DIR/internal/credentials"
mkdir -p "$BASE_DIR/internal/epp"
mkdir -p "$BASE_DIR/internal/monitor"
mkdir -p "$BASE_DIR/internal/security"
mkdir -p "$BASE_DIR/logs"

cat > "$BASE_DIR/go.mod" <<'EOF'
module telegram-epp-bot

go 1.23.0

require (
	github.com/go-telegram/bot v1.20.0
	gopkg.in/ini.v1 v1.67.0
)
EOF

cat > "$BASE_DIR/cmd/bot/main.go" <<'EOF'
package main

import (
	"log"

	"telegram-epp-bot/internal/app"
)

func main() {
	if err := app.Run(".env"); err != nil {
		log.Fatal(err)
	}
}
EOF

cat > "$BASE_DIR/internal/config/config.go" <<'EOF'
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type MonitoringConfig struct {
	Enabled        bool
	FrequencySec   int
	WaitSec        int
	SuccessRate    int
	ThresholdAlert int
	Method         string
	ObjectMethod   string
}

type MonitoringTarget struct {
	ChatID   int64
	ThreadID int
}

type Config struct {
	TelegramBotToken       string
	AllowedIdentities      map[int64]map[string]bool
	CommandAllowByIdentity map[int64]map[string]bool
	AdminChatIDs           map[int64]bool
	MonitoringTargets      []MonitoringTarget

	EPPBin             string
	CredentialsFile    string
	LocalFile          string
	DefaultSectionName string

	CommandTimeout  time.Duration
	EnableRaw       bool
	AllowedCommands map[string]bool

	LogCommands  bool
	MaskAuditLog bool
	AuditLogFile string

	MaxMessageChars      int
	SendLongOutputAsFile bool
	MaxDownloadBytes     int64

	RateLimitEnabled bool
	RateLimitCount   int
	RateLimitWindow  time.Duration

	BruteForceEnabled      bool
	BruteForceThreshold    int
	BruteForceWindow       time.Duration
	BruteForceBlock        time.Duration
	InvalidSilentDrop      bool
	ValidIdentityBlockSpam bool

	NotifyAdminOnRaw bool
	BotVersion       string

	RetryEnabled      bool
	RetryCount        int
	RetryBackoffMs    int
	RetrySafeCommands map[string]bool

	ExternalMonitoring MonitoringConfig
	InternalMonitoring MonitoringConfig
}

func Load(path string) (*Config, error) {
	envMap := map[string]string{}

	if file, err := os.Open(path); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			envMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if v, ok := envMap[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	token := get("TELEGRAM_BOT_TOKEN", "")
	if token == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN wajib diisi")
	}

	allowedIdentities, err := parseAllowedIdentities(get("ALLOWED_IDENTITIES", ""))
	if err != nil {
		return nil, err
	}
	if len(allowedIdentities) == 0 {
		return nil, errors.New("ALLOWED_IDENTITIES wajib diisi minimal 1 mapping")
	}

	commandTimeoutSec, err := parsePositiveInt(get("CMD_TIMEOUT_SECONDS", "60"), "CMD_TIMEOUT_SECONDS")
	if err != nil {
		return nil, err
	}
	maxMessageChars, err := parseMinInt(get("MAX_MESSAGE_CHARS", "3500"), "MAX_MESSAGE_CHARS", 500)
	if err != nil {
		return nil, err
	}
	maxDownloadMB, err := parsePositiveInt(get("MAX_DOWNLOAD_MB", "20"), "MAX_DOWNLOAD_MB")
	if err != nil {
		return nil, err
	}
	rateLimitCount, err := parsePositiveInt(get("RATE_LIMIT_COUNT", "5"), "RATE_LIMIT_COUNT")
	if err != nil {
		return nil, err
	}
	rateLimitWindowSec, err := parsePositiveInt(get("RATE_LIMIT_WINDOW_SECONDS", "60"), "RATE_LIMIT_WINDOW_SECONDS")
	if err != nil {
		return nil, err
	}
	retryCount, err := parsePositiveInt(get("RETRY_COUNT", "2"), "RETRY_COUNT")
	if err != nil {
		return nil, err
	}
	retryBackoffMs, err := parsePositiveInt(get("RETRY_BACKOFF_MS", "1200"), "RETRY_BACKOFF_MS")
	if err != nil {
		return nil, err
	}
	bruteForceThreshold, err := parsePositiveInt(get("BRUTE_FORCE_THRESHOLD", "10"), "BRUTE_FORCE_THRESHOLD")
	if err != nil {
		return nil, err
	}
	bruteForceWindowSec, err := parsePositiveInt(get("BRUTE_FORCE_WINDOW_SECONDS", "300"), "BRUTE_FORCE_WINDOW_SECONDS")
	if err != nil {
		return nil, err
	}
	bruteForceBlockSec, err := parsePositiveInt(get("BRUTE_FORCE_BLOCK_SECONDS", "600"), "BRUTE_FORCE_BLOCK_SECONDS")
	if err != nil {
		return nil, err
	}

	enableRaw := parseBool(get("ENABLE_RAW", "true"))
	logCommands := parseBool(get("LOG_COMMANDS", "true"))
	maskAuditLog := parseBool(get("MASK_AUDIT_LOG", "true"))
	sendLongOutputAsFile := parseBool(get("SEND_LONG_OUTPUT_AS_FILE", "true"))
	rateLimitEnabled := parseBool(get("RATE_LIMIT_ENABLED", "true"))
	notifyAdminOnRaw := parseBool(get("NOTIFY_ADMIN_ON_RAW", "true"))
	retryEnabled := parseBool(get("RETRY_ENABLED", "true"))
	bruteForceEnabled := parseBool(get("BRUTE_FORCE_ENABLED", "true"))
	invalidSilentDrop := parseBool(get("INVALID_IDENTITY_SILENT_DROP", "true"))
	validIdentityBlockSpam := parseBool(get("VALID_IDENTITY_BLOCK_SPAM", "true"))

	allowedCommands := parseCSVSet(get("ALLOWED_EPP_COMMANDS", "check,info,poll,renew,create,update,transfer,restore,delete,raw"))
	if !enableRaw {
		delete(allowedCommands, "raw")
	}

	commandAllowByIdentity, err := parseCommandAllowByIdentity(get("COMMAND_ALLOW_BY_IDENTITY", ""), allowedIdentities, allowedCommands)
	if err != nil {
		return nil, err
	}

	adminChatIDs, err := parseChatIDSet(get("ADMIN_CHAT_IDS", ""))
	if err != nil {
		return nil, err
	}

	monitoringTargets, err := parseMonitoringTargets(get("MONITORING_CHAT_IDS", ""))
	if err != nil {
		return nil, err
	}

	externalMonitoring, err := loadMonitoringConfig(get, "EXTERNAL")
	if err != nil {
		return nil, err
	}
	internalMonitoring, err := loadMonitoringConfig(get, "INTERNAL")
	if err != nil {
		return nil, err
	}

	return &Config{
		TelegramBotToken:       token,
		AllowedIdentities:      allowedIdentities,
		CommandAllowByIdentity: commandAllowByIdentity,
		AdminChatIDs:           adminChatIDs,
		MonitoringTargets:      monitoringTargets,

		EPPBin:             get("EPP_BIN", "epp"),
		CredentialsFile:    get("EPP_CREDENTIALS_FILE", "/home/leenux/.epp/credentials"),
		LocalFile:          get("EPP_LOCAL_FILE", "/home/leenux/.epp/local"),
		DefaultSectionName: get("EPP_DEFAULT_SECTION", "default"),

		CommandTimeout:  time.Duration(commandTimeoutSec) * time.Second,
		EnableRaw:       enableRaw,
		AllowedCommands: allowedCommands,

		LogCommands:  logCommands,
		MaskAuditLog: maskAuditLog,
		AuditLogFile: get("AUDIT_LOG_FILE", "/home/leenux/telegram-epp-bot/logs/audit.log"),

		MaxMessageChars:      maxMessageChars,
		SendLongOutputAsFile: sendLongOutputAsFile,
		MaxDownloadBytes:     int64(maxDownloadMB) * 1024 * 1024,

		RateLimitEnabled: rateLimitEnabled,
		RateLimitCount:   rateLimitCount,
		RateLimitWindow:  time.Duration(rateLimitWindowSec) * time.Second,

		BruteForceEnabled:      bruteForceEnabled,
		BruteForceThreshold:    bruteForceThreshold,
		BruteForceWindow:       time.Duration(bruteForceWindowSec) * time.Second,
		BruteForceBlock:        time.Duration(bruteForceBlockSec) * time.Second,
		InvalidSilentDrop:      invalidSilentDrop,
		ValidIdentityBlockSpam: validIdentityBlockSpam,

		NotifyAdminOnRaw: notifyAdminOnRaw,
		BotVersion:       get("BOT_VERSION", "v6.6.7"),

		RetryEnabled:      retryEnabled,
		RetryCount:        retryCount,
		RetryBackoffMs:    retryBackoffMs,
		RetrySafeCommands: parseCSVSet(get("RETRY_SAFE_COMMANDS", "check,info,poll,version")),

		ExternalMonitoring: externalMonitoring,
		InternalMonitoring: internalMonitoring,
	}, nil
}

func loadMonitoringConfig(get func(string, string) string, prefix string) (MonitoringConfig, error) {
	frequency, err := parsePositiveInt(get(prefix+"_FREQUENCY", "60"), prefix+"_FREQUENCY")
	if err != nil {
		return MonitoringConfig{}, err
	}
	waitSec, err := parsePositiveInt(get(prefix+"_WAIT", "300"), prefix+"_WAIT")
	if err != nil {
		return MonitoringConfig{}, err
	}
	successRate, err := parsePositiveInt(get(prefix+"_SUCCESS_RATE", "5"), prefix+"_SUCCESS_RATE")
	if err != nil {
		return MonitoringConfig{}, err
	}
	threshold, err := parsePositiveInt(get(prefix+"_TRESHOLD_ALERT", "2"), prefix+"_TRESHOLD_ALERT")
	if err != nil {
		return MonitoringConfig{}, err
	}

	return MonitoringConfig{
		Enabled:        parseBool(get(prefix+"_MONITORING", "false")),
		FrequencySec:   frequency,
		WaitSec:        waitSec,
		SuccessRate:    successRate,
		ThresholdAlert: threshold,
		Method:         strings.TrimSpace(get(prefix+"_METHOD", "")),
		ObjectMethod:   strings.TrimSpace(get(prefix+"_OBJECT_METHOD", "")),
	}, nil
}

func parseBool(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true")
}

func parsePositiveInt(s, field string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s invalid", field)
	}
	return n, nil
}

func parseMinInt(s, field string, min int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < min {
		return 0, fmt.Errorf("%s invalid", field)
	}
	return n, nil
}

func parseCSVSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out[part] = true
		}
	}
	return out
}

func parseAllowedIdentities(s string) (map[int64]map[string]bool, error) {
	out := map[int64]map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("format ALLOWED_IDENTITIES invalid: %s", item)
		}
		chatID, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("chat id invalid pada mapping: %s", item)
		}
		username := normalizeUsername(parts[1])
		if username == "" {
			return nil, fmt.Errorf("username kosong pada mapping: %s", item)
		}
		if _, ok := out[chatID]; !ok {
			out[chatID] = map[string]bool{}
		}
		out[chatID][username] = true
	}
	return out, nil
}

func parseChatIDSet(s string) (map[int64]bool, error) {
	out := map[int64]bool{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		v, err := strconv.ParseInt(item, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chat id: %s", item)
		}
		out[v] = true
	}
	return out, nil
}

func parseMonitoringTargets(s string) ([]MonitoringTarget, error) {
	out := make([]MonitoringTarget, 0)
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}

	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		parts := strings.SplitN(item, ":", 2)
		chatID, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid monitoring chat id: %s", item)
		}

		threadID := 0
		if len(parts) == 2 {
			threadID, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || threadID < 0 {
				return nil, fmt.Errorf("invalid monitoring thread id: %s", item)
			}
		}

		out = append(out, MonitoringTarget{
			ChatID:   chatID,
			ThreadID: threadID,
		})
	}

	return out, nil
}

func parseCommandAllowByIdentity(raw string, identities map[int64]map[string]bool, globalAllowed map[string]bool) (map[int64]map[string]bool, error) {
	out := map[int64]map[string]bool{}
	for chatID := range identities {
		out[chatID] = cloneSet(globalAllowed)
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}

	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("format COMMAND_ALLOW_BY_IDENTITY invalid: %s", item)
		}
		chatID, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("chat id invalid pada COMMAND_ALLOW_BY_IDENTITY: %s", item)
		}
		if _, ok := identities[chatID]; !ok {
			return nil, fmt.Errorf("chat id pada COMMAND_ALLOW_BY_IDENTITY tidak ada di ALLOWED_IDENTITIES: %d", chatID)
		}
		cmdSet := parseCSVSet(parts[1])
		if len(cmdSet) == 0 {
			return nil, fmt.Errorf("command kosong pada COMMAND_ALLOW_BY_IDENTITY: %s", item)
		}
		for cmd := range cmdSet {
			if !globalAllowed[cmd] {
				return nil, fmt.Errorf("command '%s' pada COMMAND_ALLOW_BY_IDENTITY tidak ada di ALLOWED_EPP_COMMANDS", cmd)
			}
		}
		out[chatID] = cmdSet
	}

	return out, nil
}

func cloneSet(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func normalizeUsername(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	s = strings.ToLower(s)
	return s
}
EOF

cat > "$BASE_DIR/internal/credentials/credentials.go" <<'EOF'
package credentials

import (
	"fmt"

	"gopkg.in/ini.v1"
)

type Store struct {
	defaultSection string
	cfg            *ini.File
}

func NewStore(path, defaultSection string) (*Store, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("gagal membaca credentials file: %w", err)
	}
	return &Store{
		defaultSection: defaultSection,
		cfg:            cfg,
	}, nil
}

func (s *Store) HasSection(name string) bool {
	_, err := s.cfg.GetSection(name)
	return err == nil
}

func (s *Store) DefaultSection() string {
	return s.defaultSection
}

func (s *Store) Sections() []string {
	secs := s.cfg.SectionStrings()
	out := make([]string, 0, len(secs))
	for _, sec := range secs {
		if sec == ini.DEFAULT_SECTION {
			continue
		}
		out = append(out, sec)
	}
	return out
}
EOF

cat > "$BASE_DIR/internal/audit/logger.go" <<'EOF'
package audit

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Logger struct {
	logger *log.Logger
}

func New(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("gagal membuat folder audit log: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka audit log: %w", err)
	}

	return &Logger{
		logger: log.New(f, "", log.LstdFlags),
	}, nil
}

func (l *Logger) Printf(format string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Printf(format, args...)
}

func Shorten(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
EOF

cat > "$BASE_DIR/internal/security/policy.go" <<'EOF'
package security

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"telegram-epp-bot/internal/config"
)

type rateState struct {
	count       int
	windowStart time.Time
}

type invalidState struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

type DomainLocker struct {
	mu    sync.Mutex
	locks map[string]bool
}

func NewDomainLocker() *DomainLocker {
	return &DomainLocker{
		locks: map[string]bool{},
	}
}

func (d *DomainLocker) Acquire(key string) (func(), error) {
	key = strings.TrimSpace(strings.ToLower(key))
	if key == "" {
		return func() {}, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.locks[key] {
		return nil, fmt.Errorf("domain sedang diproses: %s", key)
	}

	d.locks[key] = true
	released := false

	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if released {
			return
		}
		delete(d.locks, key)
		released = true
	}, nil
}

type Policy struct {
	cfg           *config.Config
	mu            sync.Mutex
	rateByChat    map[int64]*rateState
	invalidByChat map[int64]*invalidState
	DomainLocks   *DomainLocker
}

func NewPolicy(cfg *config.Config) *Policy {
	return &Policy{
		cfg:           cfg,
		rateByChat:    map[int64]*rateState{},
		invalidByChat: map[int64]*invalidState{},
		DomainLocks:   NewDomainLocker(),
	}
}

func (p *Policy) IsCredentialValid(chatID int64, username string) bool {
	username = normalizeUsername(username)
	users, ok := p.cfg.AllowedIdentities[chatID]
	if !ok || username == "" {
		p.recordInvalid(chatID)
		return false
	}
	if !users[username] {
		p.recordInvalid(chatID)
		return false
	}
	return true
}

func (p *Policy) recordInvalid(chatID int64) {
	if !p.cfg.BruteForceEnabled {
		return
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	st, ok := p.invalidByChat[chatID]
	if !ok {
		p.invalidByChat[chatID] = &invalidState{
			count:       1,
			windowStart: now,
		}
		return
	}

	if now.Before(st.blockedUntil) {
		return
	}

	if now.Sub(st.windowStart) >= p.cfg.BruteForceWindow {
		st.count = 1
		st.windowStart = now
		st.blockedUntil = time.Time{}
		return
	}

	st.count++
	if st.count >= p.cfg.BruteForceThreshold {
		st.blockedUntil = now.Add(p.cfg.BruteForceBlock)
		st.count = 0
		st.windowStart = now
	}
}

func (p *Policy) IsInvalidBlocked(chatID int64) bool {
	if !p.cfg.BruteForceEnabled {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	st, ok := p.invalidByChat[chatID]
	if !ok {
		return false
	}
	return time.Now().Before(st.blockedUntil)
}

func (p *Policy) ValidateCommandForIdentity(chatID int64, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command kosong")
	}

	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	if !p.cfg.AllowedCommands[cmd] {
		return fmt.Errorf("command '%s' tidak diizinkan", cmd)
	}

	if cmd == "raw" && !p.cfg.EnableRaw {
		return fmt.Errorf("command raw dinonaktifkan")
	}

	cmdSet, ok := p.cfg.CommandAllowByIdentity[chatID]
	if !ok {
		return fmt.Errorf("identity tidak terdaftar")
	}
	if !cmdSet[cmd] {
		return fmt.Errorf("command '%s' tidak diizinkan untuk identity ini", cmd)
	}

	return nil
}

func (p *Policy) CheckRateLimit(chatID int64) error {
	if !p.cfg.RateLimitEnabled {
		return nil
	}

	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	state, ok := p.rateByChat[chatID]
	if !ok {
		p.rateByChat[chatID] = &rateState{
			count:       1,
			windowStart: now,
		}
		return nil
	}

	if now.Sub(state.windowStart) >= p.cfg.RateLimitWindow {
		state.count = 1
		state.windowStart = now
		return nil
	}

	if state.count >= p.cfg.RateLimitCount {
		if p.cfg.ValidIdentityBlockSpam {
			return fmt.Errorf("Rate limit exceeded. Coba lagi nanti.")
		}
		return fmt.Errorf("Rate limit exceeded.")
	}

	state.count++
	return nil
}

func normalizeUsername(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	s = strings.ToLower(s)
	return s
}
EOF

cat > "$BASE_DIR/internal/epp/runner.go" <<'EOF'
package epp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"telegram-epp-bot/internal/config"
	"telegram-epp-bot/internal/credentials"
)

type AuditLogger interface {
	Printf(format string, args ...any)
}

type Runner struct {
	cfg       *config.Config
	credStore *credentials.Store
	audit     AuditLogger
}

type Result struct {
	Section string
	Args    []string
	Output  string
	Err     error
}

func NewRunner(cfg *config.Config, credStore *credentials.Store, audit AuditLogger) *Runner {
	return &Runner{
		cfg:       cfg,
		credStore: credStore,
		audit:     audit,
	}
}

func (r *Runner) ResolveSectionAndArgs(parts []string) (string, []string, error) {
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("format: /epp [section] <command> [arguments...]")
	}

	if len(parts) >= 2 && r.credStore.HasSection(parts[0]) {
		return parts[0], parts[1:], nil
	}

	def := r.credStore.DefaultSection()
	if !r.credStore.HasSection(def) {
		return "", nil, fmt.Errorf("section default [%s] tidak ditemukan", def)
	}

	return def, parts, nil
}

func (r *Runner) Run(section string, args []string, auditPrefix string) Result {
	attempts := 1
	if r.cfg.RetryEnabled && isRetrySafe(args, r.cfg.RetrySafeCommands) {
		attempts = r.cfg.RetryCount + 1
	}

	var last Result
	for i := 1; i <= attempts; i++ {
		last = r.runOnce(section, args, auditPrefix)
		if last.Err == nil {
			return last
		}

		if i < attempts {
			if r.audit != nil && r.cfg.LogCommands {
				r.audit.Printf("%s retry=%d section=%s cmd=%s err=%v",
					auditPrefix, i, section, strings.Join(args, " "), last.Err)
			}
			time.Sleep(time.Duration(r.cfg.RetryBackoffMs) * time.Millisecond)
		}
	}
	return last
}

func (r *Runner) runOnce(section string, args []string, auditPrefix string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.CommandTimeout)
	defer cancel()

	cliArgs := r.buildCLIArgs(section, args)

	cmd := exec.CommandContext(ctx, r.cfg.EPPBin, cliArgs...)
	cmd.Env = os.Environ()
	cmd.Stdin = bytes.NewBufferString("y\n")

	if r.cfg.LogCommands && r.audit != nil {
		r.audit.Printf("%s section=%s cli=%s %s",
			auditPrefix,
			section,
			r.cfg.EPPBin,
			strings.Join(cliArgs, " "),
		)
	}

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return Result{
			Section: section,
			Args:    cliArgs,
			Output:  string(out),
			Err:     fmt.Errorf("command timeout setelah %s", r.cfg.CommandTimeout),
		}
	}

	return Result{
		Section: section,
		Args:    cliArgs,
		Output:  string(out),
		Err:     err,
	}
}

func (r *Runner) RunSimple(args []string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.cfg.EPPBin, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = bytes.NewBufferString("y\n")

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return Result{
			Args:   args,
			Output: string(out),
			Err:    fmt.Errorf("command timeout setelah %s", r.cfg.CommandTimeout),
		}
	}

	return Result{
		Args:   args,
		Output: string(out),
		Err:    err,
	}
}

func (r *Runner) buildCLIArgs(section string, args []string) []string {
	out := make([]string, 0, len(args)+2)
	if section != "" && section != r.credStore.DefaultSection() {
		out = append(out, "-profile", section)
	}
	out = append(out, args...)
	return out
}

func isRetrySafe(args []string, safe map[string]bool) bool {
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	return safe[cmd]
}
EOF

cat > "$BASE_DIR/internal/monitor/monitor.go" <<'EOF'
package monitor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"gopkg.in/ini.v1"

	"telegram-epp-bot/internal/config"
	"telegram-epp-bot/internal/epp"
)

type sectionConfig struct {
	Name       string
	Monitoring bool
}

type sectionResult struct {
	Kind   string
	Reason string
}

type Monitor struct {
	label      string
	cfg        *config.Config
	bot        *tgbot.Bot
	runner     *epp.Runner
	sourceFile string
	mcfg       config.MonitoringConfig

	mu     sync.Mutex
	states map[string]*SectionState
	order  []string
}

type SectionState struct {
	Enabled          bool
	Status           string
	PreviousStatus   string
	Success          int
	RLE              int
	Error            int
	LastScheduledRun time.Time
	LastManualRun    time.Time
	LastReasons      []string
}

type Manager struct {
	external *Monitor
	internal *Monitor
}

func NewManager(cfg *config.Config, bot *tgbot.Bot, runner *epp.Runner) *Manager {
	return &Manager{
		external: NewMonitor("EXTERNAL", cfg, bot, runner, cfg.CredentialsFile, cfg.ExternalMonitoring),
		internal: NewMonitor("INTERNAL", cfg, bot, runner, cfg.LocalFile, cfg.InternalMonitoring),
	}
}

func NewMonitor(label string, cfg *config.Config, bot *tgbot.Bot, runner *epp.Runner, sourceFile string, mcfg config.MonitoringConfig) *Monitor {
	return &Monitor{
		label:      label,
		cfg:        cfg,
		bot:        bot,
		runner:     runner,
		sourceFile: sourceFile,
		mcfg:       mcfg,
		states:     map[string]*SectionState{},
	}
}

func (m *Manager) Start(ctx context.Context) {
	go m.external.Start(ctx)
	go m.internal.Start(ctx)
}

func (m *Manager) RunNow(ctx context.Context, target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "", "all":
		return m.external.RunNow(ctx) + "\n\n" + m.internal.RunNow(ctx)
	case "external":
		return m.external.RunNow(ctx)
	case "internal":
		return m.internal.RunNow(ctx)
	default:
		return "Target monitor tidak valid. Gunakan: external, internal, atau all"
	}
}

func (m *Manager) StatusText() string {
	return m.external.StatusText() + "\n\n" + m.internal.StatusText()
}

func (m *Manager) SectionsText() string {
	return m.external.SectionsText() + "\n\n" + m.internal.SectionsText()
}

func (m *Monitor) Start(ctx context.Context) {
	if !m.mcfg.Enabled {
		return
	}

	args, err := buildMonitoringArgs(m.mcfg.Method, m.mcfg.ObjectMethod)
	if err != nil {
		m.alert(ctx, fmt.Sprintf("[%s MONITOR]\nStatus: ERROR\nReason: method monitoring invalid\nMethod: %s\nObject: %s\nError: %v",
			m.label, m.mcfg.Method, m.mcfg.ObjectMethod, err))
		return
	}

	for {
		sections, err := loadSections(m.sourceFile)
		if err != nil {
			m.alert(ctx, fmt.Sprintf("[%s MONITOR]\nStatus: ERROR\nReason: gagal membaca source file\nFile: %s\nError: %v",
				m.label, m.sourceFile, err))
			if !sleepContext(ctx, time.Duration(m.mcfg.WaitSec)*time.Second) {
				return
			}
			continue
		}

		m.refreshSections(sections)

		for _, sec := range sections {
			if !sec.Monitoring {
				m.setDisabled(sec.Name)
				continue
			}

			m.runScheduledCycle(ctx, sec.Name, args)

			if !sleepContext(ctx, time.Duration(m.mcfg.FrequencySec)*time.Second) {
				return
			}
		}

		if !sleepContext(ctx, time.Duration(m.mcfg.WaitSec)*time.Second) {
			return
		}
	}
}

func (m *Monitor) RunNow(ctx context.Context) string {
	if !m.mcfg.Enabled {
		return fmt.Sprintf("[%s MONITOR]\nGlobalMonitoring: DISABLED", m.label)
	}

	sections, err := loadSections(m.sourceFile)
	if err != nil {
		return fmt.Sprintf("[%s MONITOR]\nStatus: ERROR\nReason: gagal membaca source file\nFile: %s\nError: %v",
			m.label, m.sourceFile, err)
	}

	m.refreshSections(sections)

	args, err := buildMonitoringArgs(m.mcfg.Method, m.mcfg.ObjectMethod)
	if err != nil {
		return fmt.Sprintf("[%s MONITOR]\nStatus: ERROR\nReason: method monitoring invalid\nMethod: %s\nObject: %s\nError: %v",
			m.label, m.mcfg.Method, m.mcfg.ObjectMethod, err)
	}

	lines := []string{
		fmt.Sprintf("[%s MONITOR RUN NOW]", m.label),
		fmt.Sprintf("Method: %s", m.mcfg.Method),
		fmt.Sprintf("Object: %s", m.mcfg.ObjectMethod),
		fmt.Sprintf("FrequencySeconds: %d", m.mcfg.FrequencySec),
		fmt.Sprintf("WaitSeconds: %d", m.mcfg.WaitSec),
	}

	for _, sec := range sections {
		if !sec.Monitoring {
			m.setDisabled(sec.Name)
			lines = append(lines, fmt.Sprintf("%s => SKIP (monitoring=false)", sec.Name))
			continue
		}

		status, success, rle, failure, reasons := m.evaluateManual(ctx, sec.Name, args)
		m.setManualState(sec.Name, success, rle, failure, reasons)
		lines = append(lines, fmt.Sprintf("%s => %s (success=%d rle=%d error=%d)", sec.Name, status, success, rle, failure))
	}

	return strings.Join(lines, "\n")
}

func (m *Monitor) StatusText() string {
	if !m.mcfg.Enabled {
		return fmt.Sprintf("[%s MONITOR STATUS]\nGlobalMonitoring: DISABLED", m.label)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	lines := []string{
		fmt.Sprintf("[%s MONITOR STATUS]", m.label),
		fmt.Sprintf("Method: %s", m.mcfg.Method),
		fmt.Sprintf("Object: %s", m.mcfg.ObjectMethod),
		fmt.Sprintf("SourceFile: %s", m.sourceFile),
		fmt.Sprintf("FrequencySeconds: %d", m.mcfg.FrequencySec),
		fmt.Sprintf("WaitSeconds: %d", m.mcfg.WaitSec),
		fmt.Sprintf("CommandsPerRun: %d", m.mcfg.SuccessRate),
	}

	for _, name := range m.order {
		st := m.states[name]
		sched := "-"
		manual := "-"
		if !st.LastScheduledRun.IsZero() {
			sched = st.LastScheduledRun.Format("2006-01-02 15:04:05")
		}
		if !st.LastManualRun.IsZero() {
			manual = st.LastManualRun.Format("2006-01-02 15:04:05")
		}
		lines = append(lines, fmt.Sprintf("%s => enabled=%t status=%s success=%d rle=%d error=%d last_scheduled_run=%s last_manual_run=%s",
			name, st.Enabled, defaultStatus(st.Status), st.Success, st.RLE, st.Error, sched, manual))
	}

	return strings.Join(lines, "\n")
}

func (m *Monitor) SectionsText() string {
	sections, err := loadSections(m.sourceFile)
	if err != nil {
		return fmt.Sprintf("[%s MONITOR SECTIONS]\nError: %v", m.label, err)
	}

	m.refreshSections(sections)

	m.mu.Lock()
	defer m.mu.Unlock()

	lines := []string{
		fmt.Sprintf("[%s MONITOR SECTIONS]", m.label),
		fmt.Sprintf("SourceFile: %s", m.sourceFile),
	}

	for _, sec := range sections {
		st := m.states[sec.Name]
		status := "INIT"
		success := 0
		rle := 0
		failure := 0
		if st != nil {
			status = defaultStatus(st.Status)
			success = st.Success
			rle = st.RLE
			failure = st.Error
		}
		lines = append(lines, fmt.Sprintf("%s => monitoring=%t status=%s success=%d rle=%d error=%d",
			sec.Name, sec.Monitoring, status, success, rle, failure))
	}

	return strings.Join(lines, "\n")
}

func (m *Monitor) evaluateManual(ctx context.Context, section string, args []string) (string, int, int, int, []string) {
	results := make([]sectionResult, 0, m.mcfg.SuccessRate)

	for i := 0; i < m.mcfg.SuccessRate; i++ {
		run := m.runner.Run(section, args, fmt.Sprintf("monitor=%s manual=true section=%s", m.label, section))
		kind, reason := classifyMonitoringResult(run)
		results = append(results, sectionResult{Kind: kind, Reason: safeReason(reason, kind)})
	}

	successCount, rleCount, errorCount, reasons := summarizeResults(results)
	status := monitoringStatus(errorCount, m.mcfg.ThresholdAlert)
	return status, successCount, rleCount, errorCount, reasons
}

func (m *Monitor) runScheduledCycle(ctx context.Context, section string, args []string) {
	results := make([]sectionResult, 0, m.mcfg.SuccessRate)

	for i := 0; i < m.mcfg.SuccessRate; i++ {
		run := m.runner.Run(section, args, fmt.Sprintf("monitor=%s scheduled=true section=%s", m.label, section))
		kind, reason := classifyMonitoringResult(run)
		results = append(results, sectionResult{Kind: kind, Reason: safeReason(reason, kind)})
	}

	successCount, rleCount, errorCount, reasons := summarizeResults(results)
	status := monitoringStatus(errorCount, m.mcfg.ThresholdAlert)

	m.mu.Lock()
	st := m.ensureState(section)
	prev := st.Status
	st.PreviousStatus = prev
	st.Status = status
	st.Success = successCount
	st.RLE = rleCount
	st.Error = errorCount
	st.LastReasons = append([]string(nil), reasons...)
	st.LastScheduledRun = time.Now()
	st.Enabled = true
	changed := prev != status
	m.mu.Unlock()

	shouldAlert := false
	if changed && status != "OK" {
		shouldAlert = true
	}
	if status == "OK" && rleCount > 0 {
		shouldAlert = true
	}

	if shouldAlert {
		m.alert(ctx, strings.Join([]string{
			fmt.Sprintf("[%s MONITOR]", m.label),
			fmt.Sprintf("Section: %s", section),
			fmt.Sprintf("Status: %s", status),
			fmt.Sprintf("PreviousStatus: %s", defaultStatus(prev)),
			fmt.Sprintf("Method: %s", m.mcfg.Method),
			fmt.Sprintf("Object: %s", m.mcfg.ObjectMethod),
			fmt.Sprintf("SourceFile: %s", m.sourceFile),
			fmt.Sprintf("FrequencySeconds: %d", m.mcfg.FrequencySec),
			fmt.Sprintf("WaitSeconds: %d", m.mcfg.WaitSec),
			fmt.Sprintf("CommandsPerRun: %d", m.mcfg.SuccessRate),
			fmt.Sprintf("Success: %d", successCount),
			fmt.Sprintf("RLE: %d", rleCount),
			fmt.Sprintf("Error: %d", errorCount),
			fmt.Sprintf("ThresholdAlert: %d", m.mcfg.ThresholdAlert),
			fmt.Sprintf("Reasons: %s", strings.Join(reasons, " | ")),
		}, "\n"))
	}
}

func summarizeResults(results []sectionResult) (int, int, int, []string) {
	successCount := 0
	rleCount := 0
	errorCount := 0
	reasons := make([]string, 0, len(results))

	for _, r := range results {
		switch r.Kind {
		case "OK":
			successCount++
		case "RLE":
			rleCount++
		default:
			errorCount++
		}
		reasons = append(reasons, r.Reason)
	}
	return successCount, rleCount, errorCount, reasons
}

func (m *Monitor) setManualState(section string, success, rle, failure int, reasons []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ensureState(section)
	st.LastManualRun = time.Now()
	st.Success = success
	st.RLE = rle
	st.Error = failure
	st.LastReasons = append([]string(nil), reasons...)
	st.Enabled = true
}

func (m *Monitor) setDisabled(section string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ensureState(section)
	st.Enabled = false
}

func (m *Monitor) refreshSections(sections []sectionConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.order = m.order[:0]
	for _, sec := range sections {
		m.order = append(m.order, sec.Name)
		st := m.ensureState(sec.Name)
		st.Enabled = sec.Monitoring
	}
}

func (m *Monitor) ensureState(section string) *SectionState {
	st, ok := m.states[section]
	if !ok {
		st = &SectionState{}
		m.states[section] = st
	}
	return st
}

func loadSections(path string) ([]sectionConfig, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, err
	}

	out := []sectionConfig{}
	for _, sec := range cfg.Sections() {
		name := sec.Name()
		if name == ini.DEFAULT_SECTION {
			continue
		}
		monitoring := strings.EqualFold(strings.TrimSpace(sec.Key("monitoring").String()), "true")
		out = append(out, sectionConfig{Name: name, Monitoring: monitoring})
	}
	return out, nil
}

func buildMonitoringArgs(method, object string) ([]string, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	object = strings.TrimSpace(object)

	if method == "" {
		return nil, fmt.Errorf("method kosong")
	}
	if object == "" {
		return nil, fmt.Errorf("object kosong")
	}

	switch method {
	case "check-domain":
		return []string{"check", object}, nil
	case "info-domain":
		return []string{"info", "domain", object}, nil
	case "info-contact":
		return []string{"info", "contact", object}, nil
	default:
		return nil, fmt.Errorf("unsupported monitoring method: %s", method)
	}
}

func classifyMonitoringResult(result epp.Result) (string, string) {
	output := strings.TrimSpace(result.Output)

	if isRateLimited(output) {
		return "RLE", "RLE"
	}

	if output == "" && result.Err != nil {
		if isRateLimited(result.Err.Error()) {
			return "RLE", "RLE"
		}
		return "ERROR", result.Err.Error()
	}
	if output == "" {
		return "ERROR", "output kosong"
	}

	code, msg, hasCode := parseEPPResult(output)
	if hasCode {
		if code == "1000" {
			return "OK", "OK"
		}
		if code == "2400" && isRateLimited(msg) {
			return "RLE", "RLE"
		}
		if msg != "" {
			if isRateLimited(msg) {
				return "RLE", "RLE"
			}
			return "ERROR", fmt.Sprintf("result code %s: %s", code, msg)
		}
		return "ERROR", fmt.Sprintf("result code %s", code)
	}

	successHints := []string{
		"Command completed successfully",
		" available",
		" unavailable",
	}
	for _, hint := range successHints {
		if strings.Contains(output, hint) {
			return "OK", "OK"
		}
	}

	if result.Err != nil {
		if isRateLimited(result.Err.Error()) {
			return "RLE", "RLE"
		}
		if msg := extractTextReason(result.Err.Error()); msg != "" {
			if isRateLimited(msg) {
				return "RLE", "RLE"
			}
			return "ERROR", msg
		}
		return "ERROR", result.Err.Error()
	}

	if msg := extractTextReason(output); msg != "" {
		if isRateLimited(msg) {
			return "RLE", "RLE"
		}
		return "ERROR", msg
	}

	return "ERROR", "result code tidak ditemukan"
}

func parseEPPResult(output string) (string, string, bool) {
	codeRe := regexp.MustCompile(`(?s)<result code="([^"]+)"`)
	msgRe := regexp.MustCompile(`(?s)<msg>([^<]+)</msg>`)

	codeMatch := codeRe.FindStringSubmatch(output)
	if len(codeMatch) < 2 {
		return "", "", false
	}
	code := strings.TrimSpace(codeMatch[1])

	msg := ""
	msgMatch := msgRe.FindStringSubmatch(output)
	if len(msgMatch) >= 2 {
		msg = strings.TrimSpace(msgMatch[1])
	}
	return code, msg, true
}

func extractTextReason(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "rate limit exceeded") {
			return line
		}
		if strings.Contains(lower, "please retry later") {
			return line
		}
		if strings.HasPrefix(lower, "error:") {
			return strings.TrimSpace(line)
		}
		if strings.Contains(lower, "reason=") {
			return line
		}
	}
	return ""
}

func isRateLimited(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "rate limit exceeded") && strings.Contains(s, "please retry later")
}

func monitoringStatus(errorCount, threshold int) string {
	if errorCount == 0 {
		return "OK"
	}
	if errorCount <= threshold {
		return "WARNING"
	}
	return "ERROR"
}

func safeReason(reason, kind string) string {
	if kind == "OK" {
		return "OK"
	}
	if kind == "RLE" {
		return "RLE"
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "UNKNOWN"
	}
	return reason
}

func defaultStatus(s string) string {
	if strings.TrimSpace(s) == "" {
		return "INIT"
	}
	return s
}

func (m *Monitor) alert(ctx context.Context, text string) {
	for _, target := range m.cfg.MonitoringTargets {
		params := &tgbot.SendMessageParams{
			ChatID:    target.ChatID,
			Text:      wrapPre(text),
			ParseMode: models.ParseModeHTML,
		}
		if target.ThreadID > 0 {
			params.MessageThreadID = target.ThreadID
		}
		_, _ = m.bot.SendMessage(ctx, params)
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func wrapPre(s string) string {
	return "<pre>" + htmlEscape(s) + "</pre>"
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
EOF

cat > "$BASE_DIR/internal/bot/handler.go" <<'EOF'
package bot

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"telegram-epp-bot/internal/audit"
	"telegram-epp-bot/internal/config"
	"telegram-epp-bot/internal/credentials"
	"telegram-epp-bot/internal/epp"
	"telegram-epp-bot/internal/monitor"
	"telegram-epp-bot/internal/security"
)

type AuditLogger interface {
	Printf(format string, args ...any)
}

type Handler struct {
	cfg        *config.Config
	bot        *tgbot.Bot
	runner     *epp.Runner
	credStore  *credentials.Store
	policy     *security.Policy
	audit      AuditLogger
	monitorMgr *monitor.Manager
}

func NewHandler(cfg *config.Config, bot *tgbot.Bot, runner *epp.Runner, credStore *credentials.Store, policy *security.Policy, audit AuditLogger, monitorMgr *monitor.Manager) *Handler {
	return &Handler{
		cfg:        cfg,
		bot:        bot,
		runner:     runner,
		credStore:  credStore,
		policy:     policy,
		audit:      audit,
		monitorMgr: monitorMgr,
	}
}

func (h *Handler) Dispatch(ctx context.Context, update *models.Update) {
	if update == nil || update.Message == nil {
		return
	}

	text := strings.TrimSpace(update.Message.Text)
	caption := strings.TrimSpace(update.Message.Caption)

	switch {
	case strings.HasPrefix(text, "/start"):
		h.Start(ctx, update)
	case strings.HasPrefix(text, "/help"):
		h.Help(ctx, update)
	case strings.HasPrefix(text, "/whoami"):
		h.WhoAmI(ctx, update)
	case strings.HasPrefix(text, "/sections"):
		h.Sections(ctx, update)
	case strings.HasPrefix(text, "/health"):
		h.Health(ctx, update)
	case strings.HasPrefix(text, "/version"):
		h.Version(ctx, update)
	case strings.HasPrefix(text, "/monitor-status"):
		h.MonitorStatus(ctx, update)
	case strings.HasPrefix(text, "/monitor-sections"):
		h.MonitorSections(ctx, update)
	case strings.HasPrefix(text, "/monitor-run-now"):
		h.MonitorRunNow(ctx, update)
	case strings.HasPrefix(text, "/epp"):
		h.EPP(ctx, update)
	case strings.HasPrefix(caption, "/epp") && update.Message.Document != nil:
		h.EPPCaption(ctx, update)
	default:
		h.Default(ctx, update)
	}
}

func (h *Handler) isAllowed(update *models.Update) bool {
	chatID, username := extractIdentity(update)
	if h.policy.IsInvalidBlocked(chatID) && h.cfg.InvalidSilentDrop {
		return false
	}
	if !h.policy.IsCredentialValid(chatID, username) {
		return false
	}
	return true
}

func (h *Handler) Default(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, "Perintah tidak dikenali. Gunakan /help")
}

func (h *Handler) Start(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, "Bot EPP aktif. Gunakan /help")
}

func (h *Handler) Help(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	msg := fmt.Sprintf(`Format:
 /epp [section] <command> [arguments...]

Command tambahan:
 /whoami
 /sections
 /health
 /version
 /monitor-status
 /monitor-sections
 /monitor-run-now
 /monitor-run-now external
 /monitor-run-now internal

Contoh:
 /epp check example.com
 /epp north check example.com
 /epp east info domain example.com
 /epp sandbox info contact fredd8
 /epp north poll
 /epp north poll -ack 12345

Raw XML:
 upload file XML sebagai document, lalu isi caption:
 /epp raw
 atau
 /epp north raw

Jika section tidak ditulis, bot memakai [%s].

Section tersedia:
 %s`,
		h.credStore.DefaultSection(),
		strings.Join(h.credStore.Sections(), ", "),
	)
	h.send(ctx, chatID, replyTo, threadID, msg)
}

func (h *Handler) WhoAmI(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, username := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, fmt.Sprintf("chat_id: %d\nusername: @%s", chatID, safeUsernameForDisplay(username)))
}

func (h *Handler) Sections(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	sections := h.credStore.Sections()
	if len(sections) == 0 {
		h.send(ctx, chatID, replyTo, threadID, "Tidak ada section yang tersedia.")
		return
	}

	msg := fmt.Sprintf("Default section: [%s]\nSections:\n- %s",
		h.credStore.DefaultSection(),
		strings.Join(sections, "\n- "),
	)
	h.send(ctx, chatID, replyTo, threadID, msg)
}

func (h *Handler) Health(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	res := h.runner.RunSimple([]string{"version"})
	if res.Err != nil {
		h.send(ctx, chatID, replyTo, threadID, fmt.Sprintf("health: NOT OK\nbinary: %s\nerror: %s\noutput:\n%s",
			h.cfg.EPPBin, res.Err.Error(), strings.TrimSpace(res.Output)))
		return
	}

	h.send(ctx, chatID, replyTo, threadID, fmt.Sprintf("health: OK\nbinary: %s\noutput:\n%s",
		h.cfg.EPPBin, strings.TrimSpace(res.Output)))
}

func (h *Handler) Version(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, fmt.Sprintf("telegram-epp-bot %s", h.cfg.BotVersion))
}

func (h *Handler) MonitorStatus(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, h.monitorMgr.StatusText())
}

func (h *Handler) MonitorSections(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)
	h.send(ctx, chatID, replyTo, threadID, h.monitorMgr.SectionsText())
}

func (h *Handler) MonitorRunNow(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, _ := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	target := "all"
	if update.Message != nil {
		fields := strings.Fields(strings.TrimSpace(update.Message.Text))
		if len(fields) >= 2 {
			target = fields[1]
		}
	}

	h.send(ctx, chatID, replyTo, threadID, h.monitorMgr.RunNow(ctx, target))
}

func (h *Handler) EPP(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, username := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	if err := h.policy.CheckRateLimit(chatID); err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	parts := fieldsAfterCommand(update.Message.Text)
	section, args, err := h.runner.ResolveSectionAndArgs(parts)
	if err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	if err := h.policy.ValidateCommandForIdentity(chatID, args); err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	if len(args) > 0 && strings.EqualFold(args[0], "raw") {
		h.send(ctx, chatID, replyTo, threadID, "Untuk command raw, upload file XML sebagai document dengan caption: /epp raw atau /epp <section> raw")
		return
	}

	release, err := h.acquireDomainLock(args)
	if err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}
	defer release()

	auditPrefix := fmt.Sprintf("chat_id=%s user=%s",
		maskChatID(chatID, h.cfg.MaskAuditLog),
		maskUsername(username, h.cfg.MaskAuditLog),
	)

	result := h.runner.Run(section, args, auditPrefix)
	h.replyResult(ctx, chatID, replyTo, threadID, section, args, result)
}

func (h *Handler) EPPCaption(ctx context.Context, update *models.Update) {
	if !h.isAllowed(update) {
		return
	}
	chatID, username := extractIdentity(update)
	replyTo := extractReplyMessageID(update)
	threadID := extractMessageThreadID(update)

	if err := h.policy.CheckRateLimit(chatID); err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	parts := fieldsAfterCommand(update.Message.Caption)
	section, args, err := h.runner.ResolveSectionAndArgs(parts)
	if err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	if err := h.policy.ValidateCommandForIdentity(chatID, args); err != nil {
		h.send(ctx, chatID, replyTo, threadID, err.Error())
		return
	}

	if len(args) == 0 || !strings.EqualFold(args[0], "raw") {
		h.send(ctx, chatID, replyTo, threadID, "Caption /epp dengan file upload hanya didukung untuk command raw.")
		return
	}

	if update.Message.Document == nil {
		h.send(ctx, chatID, replyTo, threadID, "Upload file XML sebagai document lalu isi caption: /epp raw atau /epp <section> raw")
		return
	}

	tempPath, originalName, cleanup, err := h.downloadAndValidateXMLDocument(ctx, update.Message.Document)
	if err != nil {
		h.send(ctx, chatID, replyTo, threadID, fmt.Sprintf("Gagal memproses file XML: %v", err))
		h.notifyAdmins(ctx, fmt.Sprintf("RAW rejected\nchat_id=%s\nuser=%s\nreason=%v",
			maskChatID(chatID, h.cfg.MaskAuditLog),
			maskUsername(username, h.cfg.MaskAuditLog),
			err,
		))
		return
	}
	defer cleanup()

	h.notifyAdmins(ctx, fmt.Sprintf("RAW executed\nchat_id=%s\nuser=%s\nsection=%s\nfile=%s",
		maskChatID(chatID, h.cfg.MaskAuditLog),
		maskUsername(username, h.cfg.MaskAuditLog),
		section,
		originalName,
	))

	if h.audit != nil && h.cfg.LogCommands {
		h.audit.Printf("RAW file accepted chat_id=%s user=%s section=%s file=%s",
			maskChatID(chatID, h.cfg.MaskAuditLog),
			maskUsername(username, h.cfg.MaskAuditLog),
			section,
			originalName,
		)
	}

	auditPrefix := fmt.Sprintf("chat_id=%s user=%s",
		maskChatID(chatID, h.cfg.MaskAuditLog),
		maskUsername(username, h.cfg.MaskAuditLog),
	)

	runArgs := []string{"raw", tempPath}
	result := h.runner.Run(section, runArgs, auditPrefix)

	displayArgs := []string{"raw", originalName}
	h.replyResult(ctx, chatID, replyTo, threadID, section, displayArgs, result)
}

func (h *Handler) acquireDomainLock(args []string) (func(), error) {
	key := extractDomainLockKey(args)
	return h.policy.DomainLocks.Acquire(key)
}

func extractDomainLockKey(args []string) string {
	if len(args) == 0 {
		return ""
	}

	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	switch cmd {
	case "check":
		for i := len(args) - 1; i >= 1; i-- {
			if strings.HasPrefix(args[i], "-") {
				continue
			}
			if strings.Contains(args[i], ".") {
				return normalizeDomain(args[i])
			}
		}
	case "info", "create", "renew", "delete", "restore", "transfer", "update":
		if len(args) >= 3 && strings.EqualFold(args[1], "domain") {
			return normalizeDomain(args[2])
		}
	}
	return ""
}

func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func (h *Handler) downloadAndValidateXMLDocument(ctx context.Context, doc *models.Document) (string, string, func(), error) {
	if doc == nil {
		return "", "", nil, fmt.Errorf("document kosong")
	}

	if doc.FileSize > 0 && int64(doc.FileSize) > h.cfg.MaxDownloadBytes {
		return "", "", nil, fmt.Errorf("ukuran file melebihi batas %d bytes", h.cfg.MaxDownloadBytes)
	}

	filename := sanitizeUploadedFilename(doc.FileName)
	if !strings.HasSuffix(strings.ToLower(filename), ".xml") {
		return "", "", nil, fmt.Errorf("file harus berekstensi .xml")
	}

	if !isAllowedXMLMime(doc.MimeType) {
		return "", "", nil, fmt.Errorf("mime type tidak diizinkan: %s", doc.MimeType)
	}

	file, err := h.bot.GetFile(ctx, &tgbot.GetFileParams{FileID: doc.FileID})
	if err != nil {
		return "", "", nil, fmt.Errorf("getFile gagal: %w", err)
	}

	downloadURL := h.bot.FileDownloadLink(file)
	if downloadURL == "" {
		return "", "", nil, fmt.Errorf("file download link kosong")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", "", nil, fmt.Errorf("gagal membuat request download: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", nil, fmt.Errorf("download file gagal: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("download file gagal dengan status %s", resp.Status)
	}

	tempDir, err := os.MkdirTemp("", "telegram-epp-raw-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("gagal membuat temp dir: %w", err)
	}

	cleanup := func() { _ = os.RemoveAll(tempDir) }

	dstPath := filepath.Join(tempDir, filename)
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("gagal membuat temp file: %w", err)
	}

	limited := io.LimitReader(resp.Body, h.cfg.MaxDownloadBytes+1)
	written, err := io.Copy(dst, limited)
	_ = dst.Close()
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("gagal menyimpan file download: %w", err)
	}

	if written > h.cfg.MaxDownloadBytes {
		cleanup()
		return "", "", nil, fmt.Errorf("ukuran file melebihi batas %d bytes", h.cfg.MaxDownloadBytes)
	}

	if err := validateXMLFile(dstPath); err != nil {
		cleanup()
		return "", "", nil, err
	}

	return dstPath, filename, cleanup, nil
}

func (h *Handler) notifyAdmins(ctx context.Context, msg string) {
	if !h.cfg.NotifyAdminOnRaw {
		return
	}
	for chatID := range h.cfg.AdminChatIDs {
		_, _ = h.bot.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID:    chatID,
			Text:      wrapPre(msg),
			ParseMode: models.ParseModeHTML,
		})
	}
}

func (h *Handler) send(ctx context.Context, chatID int64, replyTo int, threadID int, text string) {
	params := &tgbot.SendMessageParams{
		ChatID:    chatID,
		Text:      wrapPre(text),
		ParseMode: models.ParseModeHTML,
	}
	if threadID > 0 {
		params.MessageThreadID = threadID
	}
	if replyTo > 0 {
		params.ReplyParameters = &models.ReplyParameters{
			MessageID: replyTo,
		}
	}
	_, _ = h.bot.SendMessage(ctx, params)
}

func (h *Handler) sendDocument(ctx context.Context, chatID int64, replyTo int, threadID int, filename, content, caption string) error {
	params := &tgbot.SendDocumentParams{
		ChatID:    chatID,
		Caption:   wrapPre(caption),
		ParseMode: models.ParseModeHTML,
		Document: &models.InputFileUpload{
			Filename: filename,
			Data:     bytes.NewReader([]byte(content)),
		},
	}
	if threadID > 0 {
		params.MessageThreadID = threadID
	}
	if replyTo > 0 {
		params.ReplyParameters = &models.ReplyParameters{
			MessageID: replyTo,
		}
	}
	_, err := h.bot.SendDocument(ctx, params)
	return err
}

type parsedSummary struct {
	Command       string
	ObjectType    string
	Domain        string
	ContactID     string
	Availability  string
	Reason        string
	QueryTime     string
	ResultCode    string
	ResultMessage string
	SvTRID        string
	ExpiryDate    string
	Statuses      []string
	Roids         []string
	Registrant    string
	TransferState string
	NameServers   []string
}

func parseSummary(displayArgs []string, output string) parsedSummary {
	ps := parsedSummary{}
	if len(displayArgs) > 0 {
		ps.Command = strings.ToLower(strings.TrimSpace(displayArgs[0]))
	}
	if len(displayArgs) > 1 {
		ps.ObjectType = strings.ToLower(strings.TrimSpace(displayArgs[1]))
	}

	nonRaw, raw := splitNonRawAndRaw(output)
	src := nonRaw + "\n" + raw

	checkRe := regexp.MustCompile(`(?m)^([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+(available|unavailable)(?:\s+reason="([^"]+)")?`)
	if m := checkRe.FindStringSubmatch(nonRaw); len(m) > 0 {
		ps.Domain = m[1]
		ps.Availability = m[2]
		if len(m) > 3 {
			ps.Reason = m[3]
		}
	}

	queryRe := regexp.MustCompile(`(?m)^Query:\s*(.+)$`)
	if m := queryRe.FindStringSubmatch(nonRaw); len(m) > 1 {
		ps.QueryTime = strings.TrimSpace(m[1])
	}

	codeRe := regexp.MustCompile(`(?s)<result code="([^"]+)"`)
	if m := codeRe.FindStringSubmatch(src); len(m) > 1 {
		ps.ResultCode = strings.TrimSpace(m[1])
	}

	msgRe := regexp.MustCompile(`(?s)<msg>([^<]+)</msg>`)
	if m := msgRe.FindStringSubmatch(src); len(m) > 1 {
		ps.ResultMessage = strings.TrimSpace(m[1])
	}

	svtridRe := regexp.MustCompile(`(?s)<svTRID>([^<]+)</svTRID>`)
	if m := svtridRe.FindStringSubmatch(src); len(m) > 1 {
		ps.SvTRID = strings.TrimSpace(m[1])
	}

	nameAvailRe := regexp.MustCompile(`(?s)<name[^>]*avail="([01])"[^>]*>([^<]+)</name>`)
	if m := nameAvailRe.FindStringSubmatch(src); len(m) > 2 {
		if ps.Domain == "" {
			ps.Domain = strings.TrimSpace(m[2])
		}
		if ps.Availability == "" {
			if m[1] == "1" {
				ps.Availability = "available"
			} else {
				ps.Availability = "unavailable"
			}
		}
	}

	reasonXMLRe := regexp.MustCompile(`(?s)<reason[^>]*>([^<]+)</reason>`)
	if m := reasonXMLRe.FindStringSubmatch(src); len(m) > 1 && ps.Reason == "" {
		ps.Reason = strings.TrimSpace(m[1])
	}

	roidRe := regexp.MustCompile(`(?s)<roid[^>]*>([^<]+)</roid>`)
	for _, m := range roidRe.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 {
			ps.Roids = append(ps.Roids, strings.TrimSpace(m[1]))
		}
	}

	statusRe := regexp.MustCompile(`(?s)<status[^>]*s="([^"]+)"`)
	for _, m := range statusRe.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 {
			ps.Statuses = append(ps.Statuses, strings.TrimSpace(m[1]))
		}
	}

	exDateRe := regexp.MustCompile(`(?s)<exDate>([^<]+)</exDate>`)
	if m := exDateRe.FindStringSubmatch(src); len(m) > 1 {
		ps.ExpiryDate = strings.TrimSpace(m[1])
	}

	registrantRe := regexp.MustCompile(`(?s)<registrant>([^<]+)</registrant>`)
	if m := registrantRe.FindStringSubmatch(src); len(m) > 1 {
		ps.Registrant = strings.TrimSpace(m[1])
	}

	contactIDRe := regexp.MustCompile(`(?s)<id>([^<]+)</id>`)
	if m := contactIDRe.FindStringSubmatch(src); len(m) > 1 && ps.ObjectType == "contact" {
		ps.ContactID = strings.TrimSpace(m[1])
	}

	trStatusRe := regexp.MustCompile(`(?s)<trStatus>([^<]+)</trStatus>`)
	if m := trStatusRe.FindStringSubmatch(src); len(m) > 1 {
		ps.TransferState = strings.TrimSpace(m[1])
	}

	hostObjRe := regexp.MustCompile(`(?s)<hostObj>([^<]+)</hostObj>`)
	for _, m := range hostObjRe.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 {
			ps.NameServers = append(ps.NameServers, strings.TrimSpace(m[1]))
		}
	}

	if ps.Domain == "" && len(displayArgs) >= 3 && strings.EqualFold(displayArgs[1], "domain") {
		ps.Domain = strings.TrimSpace(displayArgs[2])
	}
	if ps.ContactID == "" && len(displayArgs) >= 3 && strings.EqualFold(displayArgs[1], "contact") {
		ps.ContactID = strings.TrimSpace(displayArgs[2])
	}

	return ps
}

func splitNonRawAndRaw(output string) (string, string) {
	marker := "--- Raw XML Log ---"
	idx := strings.Index(output, marker)
	if idx == -1 {
		return strings.TrimSpace(output), ""
	}
	return strings.TrimSpace(output[:idx]), strings.TrimSpace(output[idx:])
}

func buildSummaryMessage(defaultSection, section string, displayArgs []string, result epp.Result) string {
	cmdline := "epp " + buildDisplayCLIArgs(defaultSection, section, displayArgs)
	ps := parseSummary(displayArgs, result.Output)

	lines := []string{
		fmt.Sprintf("Section: [%s]", section),
		fmt.Sprintf("Command: %s", cmdline),
	}

	if result.Err != nil {
		lines = append(lines, "Status: ERROR")
		lines = append(lines, fmt.Sprintf("Error: %s", result.Err.Error()))
	} else {
		lines = append(lines, "Status: OK")
	}

	if ps.Command != "" {
		lines = append(lines, fmt.Sprintf("Action: %s", ps.Command))
	}
	if ps.ObjectType != "" {
		lines = append(lines, fmt.Sprintf("Object: %s", ps.ObjectType))
	}
	if ps.Domain != "" {
		lines = append(lines, fmt.Sprintf("Domain: %s", ps.Domain))
	}
	if ps.ContactID != "" {
		lines = append(lines, fmt.Sprintf("ContactID: %s", ps.ContactID))
	}
	if ps.Availability != "" {
		lines = append(lines, fmt.Sprintf("Availability: %s", ps.Availability))
	}
	if ps.Reason != "" {
		lines = append(lines, fmt.Sprintf("Reason: %s", ps.Reason))
	}
	if ps.QueryTime != "" {
		lines = append(lines, fmt.Sprintf("Query: %s", ps.QueryTime))
	}
	if ps.ResultCode != "" {
		lines = append(lines, fmt.Sprintf("ResultCode: %s", ps.ResultCode))
	}
	if ps.ResultMessage != "" {
		lines = append(lines, fmt.Sprintf("ResultMessage: %s", ps.ResultMessage))
	}
	if ps.ExpiryDate != "" {
		lines = append(lines, fmt.Sprintf("ExpiryDate: %s", ps.ExpiryDate))
	}
	if ps.Registrant != "" {
		lines = append(lines, fmt.Sprintf("Registrant: %s", ps.Registrant))
	}
	if ps.TransferState != "" {
		lines = append(lines, fmt.Sprintf("TransferState: %s", ps.TransferState))
	}
	if len(ps.Statuses) > 0 {
		lines = append(lines, fmt.Sprintf("Statuses: %s", strings.Join(unique(ps.Statuses), ", ")))
	}
	if len(ps.Roids) > 0 {
		lines = append(lines, fmt.Sprintf("ROIDs: %s", strings.Join(unique(ps.Roids), ", ")))
	}
	if len(ps.NameServers) > 0 {
		lines = append(lines, fmt.Sprintf("NameServers: %s", strings.Join(unique(ps.NameServers), ", ")))
	}
	if ps.SvTRID != "" {
		lines = append(lines, fmt.Sprintf("svTRID: %s", ps.SvTRID))
	}

	return strings.Join(lines, "\n")
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func buildDisplayCLIArgs(defaultSection, section string, args []string) string {
	out := make([]string, 0, len(args)+2)
	if section != "" && section != defaultSection {
		out = append(out, "-profile", section)
	}
	out = append(out, args...)
	return strings.Join(out, " ")
}

func extractIdentity(update *models.Update) (int64, string) {
	if update == nil || update.Message == nil {
		return 0, ""
	}
	username := ""
	if update.Message.From != nil {
		username = update.Message.From.Username
	}
	return update.Message.Chat.ID, username
}

func extractReplyMessageID(update *models.Update) int {
	if update == nil || update.Message == nil {
		return 0
	}
	return update.Message.ID
}

func extractMessageThreadID(update *models.Update) int {
	if update == nil || update.Message == nil {
		return 0
	}
	return update.Message.MessageThreadID
}

func fieldsAfterCommand(text string) []string {
	fields := strings.Fields(text)
	if len(fields) <= 1 {
		return nil
	}
	return fields[1:]
}

func maskChatID(chatID int64, enabled bool) string {
	raw := fmt.Sprintf("%d", chatID)
	if !enabled {
		return raw
	}
	if len(raw) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(raw)-4) + raw[len(raw)-4:]
}

func maskUsername(username string, enabled bool) string {
	u := strings.TrimPrefix(strings.TrimSpace(username), "@")
	if !enabled {
		if u == "" {
			return "-"
		}
		return "@" + u
	}
	if u == "" {
		return "-"
	}
	if len(u) <= 2 {
		return "@**"
	}
	return "@" + u[:2] + strings.Repeat("*", len(u)-2)
}

func safeUsernameForDisplay(username string) string {
	u := strings.TrimPrefix(strings.TrimSpace(username), "@")
	if u == "" {
		return "-"
	}
	return u
}

func buildResultFilename(section string, args []string, isError bool) string {
	status := "ok"
	if isError {
		status = "error"
	}

	cmd := "result"
	if len(args) > 0 {
		cmd = sanitizeFilenamePart(args[0])
	}

	section = sanitizeFilenamePart(section)
	return fmt.Sprintf("epp-%s-%s-%s.txt", section, cmd, status)
}

func sanitizeFilenamePart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}

	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func sanitizeUploadedFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "request.xml"
	}
	base := filepath.Base(name)
	base = sanitizeFilenamePart(base)
	if !strings.HasSuffix(strings.ToLower(base), ".xml") {
		base += ".xml"
	}
	return base
}

func isAllowedXMLMime(mime string) bool {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if mime == "" {
		return true
	}
	switch mime {
	case "application/xml", "text/xml", "application/octet-stream", "text/plain":
		return true
	default:
		return strings.Contains(mime, "xml")
	}
}

func validateXMLFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("gagal membaca file XML: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return fmt.Errorf("file XML kosong")
	}
	if trimmed[0] != '<' {
		return fmt.Errorf("file tidak tampak seperti XML")
	}

	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(trimmed, &root); err != nil {
		return fmt.Errorf("XML tidak valid: %w", err)
	}
	if root.XMLName.Local == "" {
		return fmt.Errorf("root XML tidak ditemukan")
	}

	return nil
}

func (h *Handler) replyResult(ctx context.Context, chatID int64, replyTo int, threadID int, section string, displayArgs []string, result epp.Result) {
	summary := buildSummaryMessage(h.credStore.DefaultSection(), section, displayArgs, result)
	h.send(ctx, chatID, replyTo, threadID, summary)

	body := strings.TrimSpace(result.Output)
	if body == "" {
		body = "(no output)"
	}

	if h.audit != nil && h.cfg.LogCommands {
		h.audit.Printf("response chat_id=%s section=%s summary=%s output=%s",
			maskChatID(chatID, h.cfg.MaskAuditLog),
			section,
			audit.Shorten(summary, 400),
			audit.Shorten(body, 800),
		)
	}

	wrapped := wrapPre(body)
	if h.cfg.SendLongOutputAsFile && len(wrapped) > h.cfg.MaxMessageChars {
		filename := buildResultFilename(section, displayArgs, result.Err != nil)
		_ = h.sendDocument(ctx, chatID, replyTo, threadID, filename, body, "Output terlalu panjang, dikirim sebagai file.")
		return
	}

	h.send(ctx, chatID, replyTo, threadID, body)
}

func wrapPre(s string) string {
	return "<pre>" + htmlEscape(s) + "</pre>"
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
EOF

cat > "$BASE_DIR/internal/app/app.go" <<'EOF'
package app

import (
	"context"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"telegram-epp-bot/internal/audit"
	bothandler "telegram-epp-bot/internal/bot"
	"telegram-epp-bot/internal/config"
	"telegram-epp-bot/internal/credentials"
	"telegram-epp-bot/internal/epp"
	"telegram-epp-bot/internal/monitor"
	"telegram-epp-bot/internal/security"
)

func Run(envPath string) error {
	cfg, err := config.Load(envPath)
	if err != nil {
		return err
	}

	credStore, err := credentials.NewStore(cfg.CredentialsFile, cfg.DefaultSectionName)
	if err != nil {
		return err
	}

	auditLogger, err := audit.New(cfg.AuditLogFile)
	if err != nil {
		return err
	}

	var handler *bothandler.Handler

	bot, err := tgbot.New(cfg.TelegramBotToken,
		tgbot.WithDefaultHandler(func(ctx context.Context, bot *tgbot.Bot, update *models.Update) {
			if handler != nil {
				handler.Dispatch(ctx, update)
			}
		}),
	)
	if err != nil {
		return err
	}

	policy := security.NewPolicy(cfg)
	runner := epp.NewRunner(cfg, credStore, auditLogger)
	monitorMgr := monitor.NewManager(cfg, bot, runner)
	handler = bothandler.NewHandler(cfg, bot, runner, credStore, policy, auditLogger, monitorMgr)

	go monitorMgr.Start(context.Background())

	bot.Start(context.Background())
	return nil
}
EOF

cat > "$BASE_DIR/.env" <<'EOF'
TELEGRAM_BOT_TOKEN=ISI_TOKEN_BOTFATHER

ALLOWED_IDENTITIES=106467820:freddymanullang,-863228958:freddymanullang,-863228958:shi_diq,-863228958:septianhadifajar
COMMAND_ALLOW_BY_IDENTITY=106467820=check,info,poll,renew,raw,create,update,transfer,restore,delete;-863228958=check,info

ADMIN_CHAT_IDS=106467820
MONITORING_CHAT_IDS=106467820:0,-863228958:1234

EPP_BIN=/home/linuxbrew/.linuxbrew/bin/epp
EPP_CREDENTIALS_FILE=/home/leenux/.epp/credentials
EPP_LOCAL_FILE=/home/leenux/.epp/local
EPP_DEFAULT_SECTION=default

CMD_TIMEOUT_SECONDS=60
ENABLE_RAW=true
LOG_COMMANDS=true
MASK_AUDIT_LOG=true
AUDIT_LOG_FILE=/home/leenux/telegram-epp-bot/logs/audit.log

MAX_MESSAGE_CHARS=3500
SEND_LONG_OUTPUT_AS_FILE=true
MAX_DOWNLOAD_MB=20

RATE_LIMIT_ENABLED=true
RATE_LIMIT_COUNT=5
RATE_LIMIT_WINDOW_SECONDS=60

BRUTE_FORCE_ENABLED=true
BRUTE_FORCE_THRESHOLD=10
BRUTE_FORCE_WINDOW_SECONDS=300
BRUTE_FORCE_BLOCK_SECONDS=600
INVALID_IDENTITY_SILENT_DROP=true
VALID_IDENTITY_BLOCK_SPAM=true

NOTIFY_ADMIN_ON_RAW=true
BOT_VERSION=v6.6.7

ALLOWED_EPP_COMMANDS=check,info,poll,renew,create,update,transfer,restore,delete,raw

RETRY_ENABLED=true
RETRY_COUNT=2
RETRY_BACKOFF_MS=1200
RETRY_SAFE_COMMANDS=check,info,poll,version

EXTERNAL_MONITORING=false
EXTERNAL_FREQUENCY=60
EXTERNAL_WAIT=60
EXTERNAL_SUCCESS_RATE=5
EXTERNAL_TRESHOLD_ALERT=2
EXTERNAL_METHOD=info-contact
EXTERNAL_OBJECT_METHOD=epptest

INTERNAL_MONITORING=false
INTERNAL_FREQUENCY=60
INTERNAL_WAIT=60
INTERNAL_SUCCESS_RATE=5
INTERNAL_TRESHOLD_ALERT=2
INTERNAL_METHOD=check-domain
INTERNAL_OBJECT_METHOD=pandi.id
EOF

cat > "$BASE_DIR/telegram-epp-bot.service" <<'EOF'
[Unit]
Description=Telegram EPP Bot v6.6.7
After=network.target

[Service]
Type=simple
User=leenux
Group=leenux
WorkingDirectory=/home/leenux/telegram-epp-bot
ExecStart=/home/leenux/telegram-epp-bot/telegram-epp-bot
Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false

Environment=HOME=/home/leenux

[Install]
WantedBy=multi-user.target
EOF

cd "$BASE_DIR"
go mod tidy
go build -o telegram-epp-bot ./cmd/bot

echo
echo "[OK] Installer v6.6.7 selesai."
echo
echo "Edit env:"
echo "  nano $BASE_DIR/.env"
echo
echo "Install dan restart service:"
echo "  sudo cp $BASE_DIR/telegram-epp-bot.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable telegram-epp-bot"
echo "  sudo systemctl restart telegram-epp-bot"
echo "  sudo systemctl status telegram-epp-bot"
echo
echo "Lihat audit log:"
echo "  tail -f $BASE_DIR/logs/audit.log"
echo
echo "Perubahan v6.6.7:"
echo "  - RLE tetap kategori OK"
echo "  - bot tetap kirim notifikasi jika Status=OK dan RLE>0"
echo "  - berlaku untuk 1 atau lebih RLE, maupun seluruh hasil RLE"
echo "  - reason monitoring tetap membaca XML maupun teks"
