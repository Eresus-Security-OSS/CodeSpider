package main

import (
	"context"
	"fmt"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/config"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/provider"
	githubprovider "github.com/Eresus-Security-OSS/CodeSpider/internal/provider/github"
)

func newForgeProvider(cfg config.Config) (provider.ForgeProvider, func(context.Context) (string, error), error) {
	if cfg.ForgeProvider == "github" {
		if cfg.GitHubAppID > 0 {
			source, err := githubprovider.NewAppTokenSource(cfg.GitHubBaseURL, cfg.GitHubAppID, cfg.GitHubInstallationID, cfg.GitHubAppPrivateKeyPath)
			if err != nil {
				return nil, nil, fmt.Errorf("configure GitHub App credentials: %w", err)
			}
			return githubprovider.NewClientWithTokenSource(cfg.GitHubBaseURL, source), source.Token, nil
		}
		return githubprovider.NewClient(cfg.GitHubBaseURL, cfg.GitHubToken), func(context.Context) (string, error) { return cfg.GitHubToken, nil }, nil
	}
	return &provider.GiteaAdapter{Client: gitea.NewClient(cfg.GiteaBaseURL, cfg.GiteaToken)}, func(context.Context) (string, error) { return cfg.GiteaToken, nil }, nil
}

func forgeAPIURL(cfg config.Config) string {
	if cfg.ForgeProvider == "github" {
		return cfg.GitHubBaseURL
	}
	return cfg.GiteaBaseURL
}

func forgeGitUsername(cfg config.Config) string {
	if cfg.ForgeProvider == "github" {
		return "x-access-token"
	}
	return "oauth2"
}

func forgeBotUsername(cfg config.Config) string {
	if cfg.ForgeProvider == "github" {
		return cfg.GitHubBotUsername
	}
	return cfg.GiteaBotUsername
}

func forgeRepos(cfg config.Config) []string {
	if cfg.ForgeRepos != nil {
		return cfg.ForgeRepos
	}
	if cfg.ForgeProvider == "github" {
		return cfg.GitHubRepos
	}
	return cfg.GiteaRepos
}
