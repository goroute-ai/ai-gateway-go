package router

import (
	"context"
	"sync/atomic"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

type providerDispatchKey struct{}

// TrackProviderDispatch returns a derived routing context and a getter reporting
// the first deployment that reached an adapter invocation.
func TrackProviderDispatch(ctx context.Context) (context.Context, func() *domain.Deployment) {
	if ctx == nil {
		ctx = context.Background()
	}
	var first atomic.Pointer[domain.Deployment]
	return context.WithValue(ctx, providerDispatchKey{}, &first), func() *domain.Deployment {
		return first.Load()
	}
}

func markProviderDispatch(ctx context.Context, dep *domain.Deployment) {
	if ctx == nil || dep == nil {
		return
	}
	first, ok := ctx.Value(providerDispatchKey{}).(*atomic.Pointer[domain.Deployment])
	if ok && first != nil {
		first.CompareAndSwap(nil, dep)
	}
}
