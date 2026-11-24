// Package plugin registers lint-sensitive as a golangci-lint module plugin named "sensitive".
package plugin

import (
	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"

	"github.com/powerman/lint-sensitive/analyzer"
)

func init() { //nolint:gochecknoinits // The golangci-lint module plugin system requires it.
	register.Plugin("sensitive", New)
}

// Settings are the plugin settings in .golangci.yml.
// Their keys match the flags of the lint-sensitive binary,
// except for the lists and the missing skip-tests, skip-generated and debug settings,
// see ARCHITECTURE.md ("Lifecycle and configuration").
//
//nolint:tagliatelle // The keys follow the kebab-case convention of golangci-lint settings.
type Settings struct {
	Types              []string `json:"types"`
	Public             []string `json:"public"`
	NoDefaultTypes     bool     `json:"no-default-types"`
	DetectFields       bool     `json:"detect-fields"`
	RequireMarshalJSON bool     `json:"require-marshal-json"`
	RequireMarshalText bool     `json:"require-marshal-text"`
	RequireFormat      bool     `json:"require-format"`
	RequireGoString    bool     `json:"require-gostring"`
	RequireString      bool     `json:"require-string"`
}

type plugin struct {
	cfg analyzer.Config
}

// New builds the plugin from its .golangci.yml settings.
// An unknown setting is an error.
func New(settings any) (register.LinterPlugin, error) {
	s, err := register.DecodeSettings[Settings](settings)
	if err != nil {
		return nil, err
	}
	return &plugin{cfg: analyzer.Config{
		Types:              s.Types,
		NoDefaultTypes:     s.NoDefaultTypes,
		PublicFields:       s.Public,
		DetectFields:       s.DetectFields,
		RequireMarshalJSON: s.RequireMarshalJSON,
		RequireMarshalText: s.RequireMarshalText,
		RequireFormat:      s.RequireFormat,
		RequireGoString:    s.RequireGoString,
		RequireString:      s.RequireString,
	}}, nil
}

func (p *plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return analyzer.New(p.cfg), nil
}

func (*plugin) GetLoadMode() string {
	return register.LoadModeTypesInfo
}
