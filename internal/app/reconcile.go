package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/blockmanager"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/storage"
)

// ReconcileDisabledFirewalls removes still-active elements from every supported
// backend before launch drops CAP_NET_ADMIN. The action is a router so a host
// that previously used a different backend is cleaned up as well.
func ReconcileDisabledFirewalls(ctx context.Context, cfg config.Config, blockAction action.Action, logger *slog.Logger) error {
	if config.UsesFirewall(cfg) {
		return nil
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open state for disabled firewall reconciliation: %w", err)
	}
	defer store.Close()
	policy, err := blockpolicy.New(cfg.BlockDuration)
	if err != nil {
		return err
	}
	manager, err := blockmanager.New(policy, cfg.BlockDuration, blockAction, store)
	if err != nil {
		return err
	}
	report := func(result action.Result) {
		if logger != nil {
			logger.Info("disabled firewall lease cleanup", "status", result.Status, "ip", result.IP, "reason", result.Reason, "error", result.Err)
		}
	}
	if err := manager.Restore(ctx, func(netip.Addr, string) bool { return true }, report); err != nil {
		return fmt.Errorf("remove leases after disabling firewall: %w", err)
	}
	return nil
}
