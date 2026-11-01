//go:build !containarium_client

package server

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The JWT revocation list as a late-install family (#3328, on the #3326
// helper). TokensService is registered whether or not the store exists and
// answers UNAVAILABLE until it does. After a degraded start the helper opens
// the store once Postgres answers and swaps it into the token manager, the
// TokensService and skill-run credential revocation, with no restart. While
// it is absent tokens are still validated (#3335 Q8): the degraded state is
// the family's NOT_SERVING readiness entry plus one log line per state
// change, never a silent skip.

const (
	// revocationStoreService is the family's grpc.health.v1 readiness entry.
	revocationStoreService = "containarium.revocation"
	revocationStoreDisplay = "JWT revocation list"
)

// errRevocationNotInstalled is every TokensService answer until the store
// installs.
var errRevocationNotInstalled = status.Error(codes.Unavailable,
	"token revocation list is not available yet (Postgres unavailable at startup); it installs in-process once Postgres answers — readiness "+revocationStoreService)

// revocationTokensService is the TokensService registration, made before
// the store exists. Each call goes to the TokensServer swapped in by install,
// or answers UNAVAILABLE while there is none.
type revocationTokensService struct {
	pb.UnimplementedTokensServiceServer
	live *storeSlot[*TokensServer]
}

func newRevocationTokensService() *revocationTokensService {
	return &revocationTokensService{live: newStoreSlot[*TokensServer](nil)}
}

func (s *revocationTokensService) install(srv *TokensServer) { s.live.Store(srv) }

func (s *revocationTokensService) current() (*TokensServer, error) {
	if srv := s.live.Load(); srv != nil {
		return srv, nil
	}
	return nil, errRevocationNotInstalled
}

func (s *revocationTokensService) RevokeToken(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.RevokeTokenResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.RevokeToken(ctx, req)
}

func (s *revocationTokensService) ExchangeDelegatedToken(ctx context.Context, req *pb.ExchangeDelegatedTokenRequest) (*pb.ExchangeDelegatedTokenResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.ExchangeDelegatedToken(ctx, req)
}

func (s *revocationTokensService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.RefreshToken(ctx, req)
}

func (s *revocationTokensService) ListRevokedTokens(ctx context.Context, req *pb.ListRevokedTokensRequest) (*pb.ListRevokedTokensResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.ListRevokedTokens(ctx, req)
}

func (s *revocationTokensService) GetUnscopedTokenReport(ctx context.Context, req *pb.GetUnscopedTokenReportRequest) (*pb.GetUnscopedTokenReportResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.GetUnscopedTokenReport(ctx, req)
}

// revocationConsumers are the serving paths the revocation store is
// installed into.
type revocationConsumers struct {
	tokens  *auth.TokenManager
	service *revocationTokensService
	// skillRuns is handed the store on a late install only: at startup
	// NewDualServer wires it directly, as it did before #3328.
	skillRuns *AgentSkillServer
}

// install wires st into token validation and the TokensService.
func (c revocationConsumers) install(st auth.RevocationStore) {
	c.tokens.SetRevocationStore(st)
	c.service.install(NewTokensServer(c.tokens, st, 0))
}

// registerRevocationLateInstall hands the revocation store to the helper
// after its startup install did not happen, and surfaces the degraded state:
// the token manager logs its first unchecked validation, the readiness entry
// is NOT_SERVING, and this logs the state once.
func registerRevocationLateInstall(r *storeRecovery, c revocationConsumers, open func(context.Context, *pgxpool.Pool) (auth.RevocationStore, error)) {
	c.tokens.SetRevocationPending()
	r.logf("Warning: JWT revocation list not installed (Postgres unavailable at startup): tokens are validated WITHOUT the revocation check and TokensService answers UNAVAILABLE until it installs in-process; readiness %s is NOT_SERVING", revocationStoreService)
	r.Register(storeFamily{
		Service: revocationStoreService,
		Display: revocationStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			c.install(st)
			if c.skillRuns != nil {
				c.skillRuns.SetRevocationStore(st)
			}
			r.logf("JWT revocation list enabled (installed in-process): revoked tokens are rejected again and TokensService is serving")
			return nil
		},
	})
}

// openRevocationStore opens the Postgres revocation store. It returns a true
// nil interface on error, never a nil *auth.PgRevocationStore inside one.
func openRevocationStore(ctx context.Context, pool *pgxpool.Pool) (auth.RevocationStore, error) {
	st, err := auth.NewPgRevocationStore(ctx, pool)
	if err != nil {
		return nil, err
	}
	return st, nil
}
