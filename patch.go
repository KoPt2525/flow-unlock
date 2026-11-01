package main

import (
	"fmt"
	"regexp"
	"strings"
)

// patch.go is a Go port of patch.js from the "Flow Local Test Runner" Chrome
// extension. It applies the same two adaptive strategies, preserving the
// uniqueness checks and the error messages.
//
// Strategy 1 ("route-guard-v1"): find the single regional guard
// `if(!X()) return ... "/unsupported-country"` and the single age guard
// `if(!X()) return ... "/age-restricted"`, then replace the regional guard with
// `if(false)` so the regional redirect never fires.
//
// Strategy 2 ("known-field-accessor-v1"): fallback for older bundles that read
// the regional/age flags through `_.uu(a, 31)` / `_.uu(a, 32)` accessors.
// It replaces the regional accessor with `true`.

const (
	// countryGuard matches `if ( ! IDENT ( . IDENT )* ( ) )` exactly.
	// Go regexp (RE2) has no lookahead, so we capture the guard and require the
	// following `return ... "/unsupported-country"` in the same match.
	countryRouteReStr = `(if\(\s*!\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\(\)\s*\))return[^;]{0,256}["']/unsupported-country["']`
	ageRouteReStr      = `(if\(\s*!\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\(\)\s*\))return[^;]{0,256}["']/age-restricted["']`

	regionFlagReStr = `_\.(?:uu|pu)\(a,\s*31\)`
	ageFlagReStr    = `_\.(?:uu|pu)\(a,\s*32\)`
)

var (
	countryRouteRe = regexp.MustCompile(countryRouteReStr)
	ageRouteRe     = regexp.MustCompile(ageRouteReStr)
	regionFlagRe   = regexp.MustCompile(regionFlagReStr)
	ageFlagRe      = regexp.MustCompile(ageFlagReStr)
)

// PatchResult describes the outcome of an attempt to patch the bundle source.
type PatchResult struct {
	OK       bool   `json:"ok"`
	Source   string `json:"-"`
	Strategy string `json:"strategy,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PatchSource applies the adaptive patch to a decoded bundle body.
func PatchSource(source string) PatchResult {
	if strings.TrimSpace(source) == "" {
		return PatchResult{OK: false, Source: source, Error: "Bundle source is empty or invalid."}
	}

	route := patchRouteGuard(source)
	if route.OK {
		return route
	}

	field := patchKnownFieldAccessor(source)
	if field.OK {
		return field
	}

	return PatchResult{
		OK:     false,
		Source: source,
		Error:  route.Error + " " + field.Error,
	}
}

func patchRouteGuard(source string) PatchResult {
	countryMatches := countryRouteRe.FindAllString(source, -1)
	ageMatches := ageRouteRe.FindAllString(source, -1)

	if len(countryMatches) == 1 && len(ageMatches) == 1 {
		patched := replaceFirstGroup(source, countryRouteRe, "if(false)")
		remainingCountry := len(countryRouteRe.FindAllString(patched, -1))
		remainingAge := len(ageRouteRe.FindAllString(patched, -1))

		if remainingCountry == 0 && remainingAge == 1 {
			return PatchResult{OK: true, Source: patched, Strategy: "route-guard-v1"}
		}
	}

	return PatchResult{
		OK:     false,
		Source: source,
		Error: fmt.Sprintf(
			"Adaptive route guard was not unique (country=%d, age=%d).",
			len(countryMatches), len(ageMatches),
		),
	}
}

func patchKnownFieldAccessor(source string) PatchResult {
	regionMatches := regionFlagRe.FindAllString(source, -1)
	ageMatches := ageFlagRe.FindAllString(source, -1)

	if len(regionMatches) != 1 || len(ageMatches) != 1 {
		return PatchResult{
			OK:     false,
			Source: source,
			Error: fmt.Sprintf(
				"Known field accessor was not unique (region=%d, age=%d).",
				len(regionMatches), len(ageMatches),
			),
		}
	}

	return PatchResult{
		OK:       true,
		Source:   regionFlagRe.ReplaceAllString(source, "true"),
		Strategy: "known-field-accessor-v1",
	}
}

// replaceFirstGroup replaces only capture group 1 of the first match of re.
// The compiled patterns above all have exactly one capturing group (the guard),
// so group 1 is the span we want to substitute.
func replaceFirstGroup(source string, re *regexp.Regexp, replacement string) string {
	loc := re.FindStringSubmatchIndex(source)
	if loc == nil {
		return source
	}
	// loc[2], loc[3] are the start/end of capture group 1.
	return source[:loc[2]] + replacement + source[loc[3]:]
}
