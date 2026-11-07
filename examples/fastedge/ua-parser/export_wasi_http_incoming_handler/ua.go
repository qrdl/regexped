package export_wasi_http_incoming_handler

import (
	"errors"
	"strings"

	m "wit_component/regexped_uaparser_matcher"
	"wit_component/regexped_uaparser_sets"

	witTypes "go.bytecodealliance.org/pkg/wit/types"
)

// Result is the answer. A category nothing matched is nil, null in the JSON.
type Result struct {
	Browser *Named
	OS      *Named
	Device  string // mobile, tablet, desktop or unknown
	Bot     *Named
}

// Named is a browser, an OS or a bot, with its version when the
// User-Agent string carries one.
type Named struct {
	Name    string
	Version *string
}

// AppendJSON writes r as
// {"browser":{"name":…,"version":…},"os":…,"device":…,"bot":…}.
// Written out by hand rather than with encoding/json, which doubles the
// app's code (1.6 MB → 3.1 MB) and the time to compile it.
func (r Result) AppendJSON(b []byte) []byte {
	b = append(b, `{"browser":`...)
	b = r.Browser.appendJSON(b)
	b = append(b, `,"os":`...)
	b = r.OS.appendJSON(b)
	b = append(b, `,"device":`...)
	b = appendString(b, r.Device)
	b = append(b, `,"bot":`...)
	b = r.Bot.appendJSON(b)
	return append(b, '}')
}

func (n *Named) appendJSON(b []byte) []byte {
	if n == nil {
		return append(b, "null"...)
	}
	b = append(b, `{"name":`...)
	b = appendString(b, n.Name)
	b = append(b, `,"version":`...)
	if n.Version == nil {
		b = append(b, "null"...)
	} else {
		b = appendString(b, *n.Version)
	}
	return append(b, '}')
}

// appendString writes s as a JSON string. Every value here comes from a
// pattern's capture or a fixed name, so escaping is rarely needed, but a
// User-Agent string is client input.
func appendString(b []byte, s string) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// errUnknown is a regexped error code (the Backtracking engine gave up): the
// answer is unknown, which is not the same as "no match".
var errUnknown = errors.New("the regexp engine could not answer")

// groups is what every pattern's groups export gives: a resource whose Next
// returns the next match's groups — index 0 the whole match, an unset group
// none — and whose Drop releases it.
type groups interface {
	Next() witTypes.Result[[]witTypes.Option[witTypes.Tuple2[uint32, uint32]], uint8]
	Drop()
}

type pattern struct {
	name   string
	groups func(input []byte) groups // nil: the pattern has no groups export
}

// patterns follows regexped.yaml's `patterns:` ORDER: a set member's id is its
// index there. Within a category the first one present wins.
var patterns = []pattern{
	// Browsers, ids 0-11.
	{"Edge", func(b []byte) groups { return m.MakeEdgeVersion(b, 0) }},
	{"Opera", func(b []byte) groups { return m.MakeOperaVersion(b, 0) }},
	{"Samsung Internet", func(b []byte) groups { return m.MakeSamsungVersion(b, 0) }},
	{"Yandex Browser", func(b []byte) groups { return m.MakeYandexVersion(b, 0) }},
	{"Vivaldi", func(b []byte) groups { return m.MakeVivaldiVersion(b, 0) }},
	{"UC Browser", func(b []byte) groups { return m.MakeUcVersion(b, 0) }},
	{"DuckDuckGo", func(b []byte) groups { return m.MakeDuckduckgoVersion(b, 0) }},
	{"Firefox", func(b []byte) groups { return m.MakeFirefoxVersion(b, 0) }},
	{"Chrome", func(b []byte) groups { return m.MakeChromeVersion(b, 0) }},
	{"Safari", func(b []byte) groups { return m.MakeSafariVersion(b, 0) }},
	{"Internet Explorer", func(b []byte) groups { return m.MakeIeVersion(b, 0) }},
	{"Internet Explorer", func(b []byte) groups { return m.MakeIe11Version(b, 0) }},
	// Operating systems, ids 12-17.
	{"iOS", func(b []byte) groups { return m.MakeIosVersion(b, 0) }},
	{"Android", func(b []byte) groups { return m.MakeAndroidVersion(b, 0) }},
	{"ChromeOS", func(b []byte) groups { return m.MakeChromeosVersion(b, 0) }},
	{"Windows", func(b []byte) groups { return m.MakeWindowsVersion(b, 0) }},
	{"macOS", func(b []byte) groups { return m.MakeMacosVersion(b, 0) }},
	{"Linux", nil},
	// Device type, ids 18-19.
	{"tablet", nil},
	{"mobile", nil},
	// Bots, ids 20-22.
	{"crawler", func(b []byte) groups { return m.MakeCrawlerName(b, 0) }},
	{"tool", func(b []byte) groups { return m.MakeToolName(b, 0) }},
	{"unidentified bot", nil},
}

const (
	browsersFrom, osFrom, devicesFrom, botsFrom, end = 0, 12, 18, 20, 23
	idIOS, idAndroid, idWindows, idMacOS             = 12, 13, 15, 16
	idTablet, idMobile, idCrawler, idTool            = 18, 19, 20, 21
)

// windowsNames turns the kernel version a User-Agent carries into the release
// name. Windows 11 still says "Windows NT 10.0".
var windowsNames = map[string]string{"10.0": "10", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP"}

func parse(ua []byte) (Result, error) {
	var res Result
	// One scan answers every pattern at once.
	all := regexped_uaparser_sets.Classify(ua, 0)
	if all.IsErr() {
		return res, errUnknown
	}
	var present [end]bool
	for _, id := range all.Ok() {
		present[id] = true
	}
	first := func(from, to int) int {
		for id := from; id < to; id++ {
			if present[id] {
				return id
			}
		}
		return -1
	}

	if id := first(browsersFrom, osFrom); id >= 0 {
		g, err := captures(id, ua)
		if err != nil {
			return res, err
		}
		res.Browser = &Named{Name: patterns[id].name, Version: g.at(1)}
	}

	osID := first(osFrom, devicesFrom)
	if osID >= 0 {
		res.OS = &Named{Name: patterns[osID].name}
		if patterns[osID].groups != nil {
			g, err := captures(osID, ua)
			if err != nil {
				return res, err
			}
			res.OS.Version = g.at(1)
		}
		if v := res.OS.Version; v != nil {
			switch osID {
			case idIOS, idMacOS: // 17_2 → 17.2
				s := strings.ReplaceAll(*v, "_", ".")
				res.OS.Version = &s
			case idWindows:
				if name, ok := windowsNames[*v]; ok {
					res.OS.Version = &name
				}
			}
		}
	}

	switch {
	case present[idTablet]:
		res.Device = "tablet"
	case present[idMobile]:
		res.Device = "mobile"
	case osID == idAndroid: // Android without "Mobile" is a tablet
		res.Device = "tablet"
	case osID > idAndroid: // ChromeOS, Windows, macOS, Linux
		res.Device = "desktop"
	default:
		res.Device = "unknown"
	}

	switch id := first(botsFrom, end); id {
	case idCrawler, idTool:
		g, err := captures(id, ua)
		if err != nil {
			return res, err
		}
		if name := g.at(1); name != nil {
			res.Bot = &Named{Name: *name, Version: g.at(2)}
		}
	case -1:
	default:
		res.Bot = &Named{Name: patterns[id].name}
	}
	return res, nil
}

// spans is one match's groups as text: nil for a group that did not take part.
type spans []*string

func (s spans) at(i int) *string {
	if i < len(s) {
		return s[i]
	}
	return nil
}

// captures returns the groups of pattern id's first match in ua.
func captures(id int, ua []byte) (spans, error) {
	g := patterns[id].groups(ua)
	defer g.Drop()
	next := g.Next()
	if next.IsErr() {
		return nil, errUnknown
	}
	var out spans
	for _, o := range next.Ok() {
		if !o.IsSome() {
			out = append(out, nil)
			continue
		}
		s := string(ua[o.Some().F0:o.Some().F1])
		out = append(out, &s)
	}
	return out, nil
}
