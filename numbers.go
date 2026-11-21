package sigma

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// numberScalar exists only for detection operands. text is captured from the
// YAML tag and source before any legacy float conversion. Immutable text can
// be shared internally; each exported condition occurrence is charged by
// copyCondition, including the authoritative numeric operand.
type numberScalar struct {
	text, legacy string
	nonfinite    bool // valid YAML, representable only when the modifier consumes text
}

type scalarIdentity struct{ text, number string }

func scalarKey(value any, numberText string) scalarIdentity {
	if numberText != "" {
		return scalarIdentity{number: numberText}
	}
	return scalarIdentity{text: formatScalar(value)}
}

func decodeNumber(node *yaml.Node, b *parseBudget) (numberScalar, error) {
	raw := node.Value
	b.step(len(raw) + 1)
	if strings.Contains(raw, "_") {
		b.output(len(raw))
		b.step(len(raw))
		raw = strings.ReplaceAll(raw, "_", "")
	}
	var text, legacy string
	if node.Tag == "!!int" {
		unsigned := raw
		if len(raw) > 0 && (raw[0] == '+' || raw[0] == '-') {
			unsigned = raw[1:]
		}
		b.step(len(unsigned))
		decimal := len(unsigned) > 0 && (len(unsigned) == 1 || unsigned[0] != '0')
		for _, c := range unsigned {
			decimal = decimal && c >= '0' && c <= '9'
		}
		if decimal {
			// Decimal coefficients need no big integer conversion at all.
			legacy = strings.TrimPrefix(raw, "+")
			text = canonicalDecimal(raw, b)
			return numberScalar{text: text, legacy: legacy}, nil
		}
		// Base conversion uses bounded big integer arithmetic. Reserve its digit
		// storage, decimal rendering and conservative quadratic work before parsing.
		b.step(b.product(len(raw), len(raw), b.limits.work-b.work, "work"))
		b.output(b.product(len(raw)+1, 2, b.limits.outputBytes-b.outputBytes, "output bytes"))
		value, ok := new(big.Int).SetString(raw, 0)
		if !ok {
			return numberScalar{}, fmt.Errorf("invalid YAML integer")
		}
		legacy = value.String()
		text = canonicalDecimal(legacy, b)
	} else {
		if !numericTextRe.MatchString(raw) {
			// YAML itself validates exceptional float spelling. Keep its provenance
			// until the field/modifier role is known: .inf may be textual contains,
			// but can never become an exact JSON numeric operand.
			b.step(len(raw))
			var value float64
			if err := node.Decode(&value); err != nil || (!math.IsInf(value, 0) && !math.IsNaN(value)) {
				return numberScalar{}, fmt.Errorf("unsupported or invalid YAML number")
			}
			b.output(4)
			b.step(4) // +Inf, -Inf or NaN, before formatting
			return numberScalar{legacy: strconv.FormatFloat(value, 'f', -1, 64), nonfinite: true}, nil
		}
		text = canonicalDecimal(raw, b)
		// Preserve the legacy formatted Value for existing finite floats. It is
		// never used to infer NumberText. Overflowing exponents keep compact exact
		// text instead of expanding the exponent into an unbounded decimal string.
		if !strings.ContainsAny(raw, ".eE") {
			legacy = strings.TrimPrefix(raw, "+")
		} else if value, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsInf(value, 0) && !math.IsNaN(value) {
			b.output(327)
			b.step(327) // maximum finite binary64 fixed-format length
			legacy = strconv.FormatFloat(value, 'f', -1, 64)
		} else {
			legacy = text
		}
	}
	return numberScalar{text: text, legacy: legacy}, nil
}

// canonicalDecimal expresses an exact decimal as an unsigned digit coefficient
// (with optional leading minus) and a decimal exponent. Leading and trailing
// coefficient zeros disappear. Exponents remain compact; their numeric value
// never controls an allocation. The existing work budget bounds big integer
// exponent arithmetic before it starts; there is no independent numeric cap.
func canonicalDecimal(raw string, b *parseBudget) string {
	b.step(len(raw) + 1)
	negative := strings.HasPrefix(raw, "-")
	unsigned := strings.TrimPrefix(strings.TrimPrefix(raw, "+"), "-")
	mantissa, exponentText := unsigned, "0"
	if at := strings.IndexAny(unsigned, "eE"); at >= 0 {
		mantissa, exponentText = unsigned[:at], unsigned[at+1:]
	}
	fraction := 0
	if at := strings.IndexByte(mantissa, '.'); at >= 0 {
		fraction = len(mantissa) - at - 1
	}
	b.output(len(mantissa))
	b.step(len(mantissa))
	digits := strings.ReplaceAll(mantissa, ".", "")
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	adjustment := len(digits) - len(trimmed) - fraction
	digits = trimmed
	// Reserve exponent parse/copy work and storage, including carry digits from
	// adding the source-length adjustment, before big.Int or String allocate.
	if exponentText == "0" && adjustment == 0 {
		sign := ""
		if negative {
			sign = "-"
		}
		b.step(len(sign) + len(digits))
		b.output(len(sign) + len(digits))
		return sign + digits
	}
	n := len(exponentText) + 24
	b.step(b.product(n, n, b.limits.work-b.work, "work"))
	b.output(b.product(n, 3, b.limits.outputBytes-b.outputBytes, "output bytes"))
	exponent, ok := new(big.Int).SetString(exponentText, 10)
	if !ok {
		panic(parseAbort{fmt.Errorf("invalid YAML numeric exponent")})
	}
	exponent.Add(exponent, big.NewInt(int64(adjustment)))
	suffix := ""
	if exponent.Sign() != 0 {
		suffix = "e" + exponent.String()
	}
	sign := ""
	if negative {
		sign = "-"
	}
	b.step(len(sign) + len(digits) + len(suffix))
	b.output(len(sign) + len(digits) + len(suffix))
	return sign + digits + suffix
}
