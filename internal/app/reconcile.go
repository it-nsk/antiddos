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

// ReconcileDisabledNFTables removes still-active firewall elements and leases
// before launch drops CAP_NET_ADMIN for a configuration with no nftables rules.
// When at least one nftables rule remains, Run performs the finer per-rule
// reconciliation while retaining the capability.
func ReconcileDisabledNFTables(ctx context.Context, cfg config.Config, blockAction action.Action, logger *slog.Logger) error {
	if config.UsesNFTables(cfg) {
		return nil
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open state for disabled nftables reconciliation: %w", err)
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
			logger.Info("disabled nftables lease cleanup", "status", result.Status, "ip", result.IP, "reason", result.Reason, "error", result.Err)
		}
	}
	if err := manager.Restore(ctx, func(netip.Addr, string) bool { return true }, report); err != nil {
		return fmt.Errorf("remove leases after disabling nftables: %w", err)
	}
	return nil
}
