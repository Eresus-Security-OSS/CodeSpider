// Package sarif exports CodeSpider evidence and secret-scan findings in SARIF 2.1.0 format.
package sarif

import (
	"encoding/json"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
)

type logDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int64 `json:"startLine"`
	EndLine   int64 `json:"endLine,omitempty"`
}

// Marshal serializes findings and secret scan alerts as SARIF 2.1.0 JSON.
func Marshal(findings []evidence.Finding, secrets []security.Finding) ([]byte, error) {
	results := make([]result, 0, len(findings)+len(secrets))

	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = "CS-AGENT-001"
		}
		start := f.StartLine
		if start <= 0 {
			start = f.EndLine
		}
		if start <= 0 {
			start = 1
		}
		res := result{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: message{Text: f.Body},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.Path},
					Region:           &region{StartLine: start, EndLine: f.EndLine},
				},
			}},
			Properties: map[string]any{
				"evidenceState":   f.State,
				"evidence":        f.Evidence,
				"counterEvidence": f.CounterEvidence,
				"limitations":     f.Limitations,
			},
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"codespider/v1": f.Fingerprint}
		}
		results = append(results, res)
	}

	for _, s := range secrets {
		line := int64(s.Line)
		if line <= 0 {
			line = 1
		}
		results = append(results, result{
			RuleID:  "CS-SECRET-001",
			Level:   "error",
			Message: message{Text: s.Kind + " (" + s.MaskedPreview + ") detected in commit history"},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: s.File},
					Region:           &region{StartLine: line},
				},
			}},
			Properties: map[string]any{
				"evidenceState": evidence.StateStaticallySupported,
				"inHistoryOnly": s.InHistoryOnly,
				"commitSHA":     s.CommitSHA,
			},
		})
	}

	doc := logDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{
				Driver: driver{
					Name:           "CodeSpider",
					InformationURI: "https://github.com/Eresus-Security-OSS/CodeSpider",
				},
			},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical":
		return "error"
	case "warning":
		return "warning"
	default:
		return "note"
	}
}
