//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

type windowsService struct {
	cfg config
}

func runPlatform(cfg config) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isService {
		return svc.Run("zeno-agent", &windowsService{cfg: cfg})
	}
	return runConsole(cfg)
}

func (s *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, s.cfg)
	}()
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-errCh:
			statuses <- svc.Status{State: svc.Stopped}
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("zeno-agent service stopped with error: %v", err)
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-errCh:
					statuses <- svc.Status{State: svc.Stopped}
					if err != nil && !errors.Is(err, context.Canceled) {
						log.Printf("zeno-agent service stopped with error: %v", err)
						return false, 1
					}
					return false, 0
				case <-time.After(20 * time.Second):
					log.Printf("zeno-agent service stop timed out")
					statuses <- svc.Status{State: svc.Stopped}
					return false, 1
				}
			default:
				log.Printf("unexpected service control request: %v", request.Cmd)
			}
		}
	}
}
