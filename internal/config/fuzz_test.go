package config

import "testing"

func FuzzParseConfigYAML(f *testing.F) {
	f.Add("gitea:\n  base_url: \"https://gitea.local\"\n  token: \"tok\"\n")
	f.Add("agent:\n  default_skills:\n    - security\n    - testing\n")
	f.Fuzz(func(t *testing.T, content string) {
		cfg := Default()
		_ = parseYAML(content, &cfg)
	})
}
