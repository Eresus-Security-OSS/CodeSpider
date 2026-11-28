package repoconfig

import (
	"os"
	"strings"
)

// FileReader returns the contents of a repo-relative file.
type FileReader func(rel string) ([]byte, error)

// buildInstructions joins the repository instruction files (read through read) and the
// .codespider.yaml instructions into one prompt section.
func buildInstructions(read FileReader, yamlInstructions string) string {
	var sections []string
	for _, rel := range instructionFiles {
		raw, err := read(rel)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		if text == "" {
			continue
		}
		if len(text) > maxInstructionBytes {
			text = text[:maxInstructionBytes] + "\n... (truncated)"
		}
		sections = append(sections, "### From "+rel+"\n"+text)
	}
	if yamlInstructions != "" {
		sections = append(sections, "### From .codespider.yaml\n"+strings.TrimSpace(yamlInstructions))
	}
	return strings.Join(sections, "\n\n")
}

// LoadFromBase builds the configuration for an untrusted fork PR. Nothing is read from the
// PR head: settings, instructions, and path_instructions all come from the base branch
// (trustedBaseYAML plus the instruction files returned by readBase). The repository keeps
// its review rules, while a fork author cannot inject prompt instructions or change gates.
func LoadFromBase(trustedBaseYAML []byte, readBase FileReader) Config {
	cfg := Config{Enabled: true, ForbidImports: make(map[string][]string)}
	if len(trustedBaseYAML) > 0 {
		parseYAMLSubset(string(trustedBaseYAML), &cfg)
	}
	if readBase == nil {
		readBase = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	}
	cfg.Instructions = buildInstructions(readBase, cfg.Instructions)
	return cfg
}
