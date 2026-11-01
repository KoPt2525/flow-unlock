package main

import (
	"strings"
	"testing"
)

func TestPatchSource_RouteGuard(t *testing.T) {
	src := `xx;if(!Qa())return this.router.navigateByUrl("/unsupported-country");yy;if(!Rb())return n("/age-restricted");zz`

	res := PatchSource(src)
	if !res.OK {
		t.Fatalf("expected OK, got error %q", res.Error)
	}
	if res.Strategy != "route-guard-v1" {
		t.Fatalf("expected strategy route-guard-v1, got %q", res.Strategy)
	}
	if !strings.Contains(res.Source, "if(false)return this.router.navigateByUrl") {
		t.Fatalf("expected the country guard to be replaced by if(false), got:\n%s", res.Source)
	}
	if strings.Contains(res.Source, "if(!Qa())") {
		t.Fatalf("country guard should have been removed")
	}
	if !strings.Contains(res.Source, "if(!Rb())return n(\"/age-restricted\")") {
		t.Fatalf("age guard should remain untouched")
	}
}

func TestPatchSource_RouteGuard_SingleQuotes(t *testing.T) {
	src := `if(!this.isCountrySupported())return this.router.navigateByUrl('/unsupported-country');if(!this.isAgeOk())return this.router.navigateByUrl('/age-restricted');`

	res := PatchSource(src)
	if !res.OK {
		t.Fatalf("expected OK, got error %q", res.Error)
	}
	if !strings.Contains(res.Source, "if(false)return this.router.navigateByUrl('/unsupported-country')") {
		t.Fatalf("country guard should be replaced:\n%s", res.Source)
	}
}

func TestPatchSource_KnownFieldAccessor(t *testing.T) {
	src := `if(_.uu(a, 31))return"/unsupported-country";if(_.uu(a, 32))return"/age-restricted";`

	res := PatchSource(src)
	if !res.OK {
		t.Fatalf("expected OK, got error %q", res.Error)
	}
	if res.Strategy != "known-field-accessor-v1" {
		t.Fatalf("expected strategy known-field-accessor-v1, got %q", res.Strategy)
	}
	if !strings.Contains(res.Source, "if(true)return\"/unsupported-country\"") {
		t.Fatalf("expected region accessor replaced with true, got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "_.uu(a, 32)") {
		t.Fatalf("age accessor should remain untouched")
	}
}

func TestPatchSource_NonUniqueCountry(t *testing.T) {
	src := `if(!A())return x("/unsupported-country");if(!B())return y("/unsupported-country");if(!C())return z("/age-restricted");`

	res := PatchSource(src)
	if res.OK {
		t.Fatalf("expected failure for non-unique country guard")
	}
	if !strings.Contains(res.Error, "country=2") {
		t.Fatalf("expected country=2 in error, got %q", res.Error)
	}
}

func TestPatchSource_Empty(t *testing.T) {
	res := PatchSource("   ")
	if res.OK {
		t.Fatalf("expected failure for empty source")
	}
	if !strings.Contains(res.Error, "empty") {
		t.Fatalf("expected empty error, got %q", res.Error)
	}
}

func TestPatchSource_NoMatch(t *testing.T) {
	res := PatchSource("function totallyUnrelated() { return 1; }")
	if res.OK {
		t.Fatalf("expected failure when nothing matches")
	}
	if !strings.Contains(res.Error, "not unique") {
		t.Fatalf("expected uniqueness error, got %q", res.Error)
	}
}
