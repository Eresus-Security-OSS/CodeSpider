package worker

import (
	"context"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
)

// baseFileReader returns a reader for files on the PR's base branch (from the cached mirror),
// or nil when the workspace or base ref is unavailable. Fork PRs use it so that repository
// rules come from trusted history instead of the fork's head.
func (p *Pool) baseFileReader(ctx context.Context, t gitea.ReviewTrigger) repoconfig.FileReader {
	if p.workspace == nil || t.BaseRef == "" {
		return nil
	}
	return func(rel string) ([]byte, error) {
		return p.workspace.ReadMirrorFile(ctx, t.Owner, t.Repo, t.BaseRef, rel)
	}
}
