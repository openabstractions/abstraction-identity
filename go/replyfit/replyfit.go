// Package replyfit keeps a read reply useful when one part of it fails the
// generated codec. A list entry the reader refuses is dropped, a list that
// overflows the reply frame is cut where it overflows, and every change is
// reported in one line naming the field path. The rest of the reply is
// returned.
//
// Fit is for read, list and display replies only. A request that changes
// state and a record that carries authority keep strict validation: their
// callers refuse the whole value.
package replyfit

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// Error names the part of a reply that could not be kept, as
// field:<path>:<why>. Path is "reply" when the fault is the reply's own
// envelope fields rather than a named member.
type Error struct {
	Path string
	Why  string
}

func (e *Error) Error() string { return "field:" + e.Path + ":" + e.Why }

// Fit returns value unchanged when check accepts it. check runs a candidate
// through the generated writer, reader and frame bound, the same path a
// client reads. Otherwise Fit works on a deep copy: it drops each list entry
// check refuses on its own and cuts each list where the entries that fit
// alone stop fitting together, reporting each change to report as
// "field:<path>:<why>; ...". The error is an *Error when the copy still
// fails, which happens when a field outside every list is refused.
func Fit[T any](value T, check func(T) error, report func(string)) (T, error) {
	return fit(value, check, report, false)
}

// FitWhole is Fit for replies whose list entries are only meaningful
// complete, such as command declarations with their schemas: an entry the
// reader refuses is dropped whole, and the lists inside a kept entry are
// never cut.
func FitWhole[T any](value T, check func(T) error, report func(string)) (T, error) {
	return fit(value, check, report, true)
}

func fit[T any](value T, check func(T) error, report func(string), whole bool) (T, error) {
	if check(value) == nil {
		return value, nil
	}
	if report == nil {
		report = func(string) {}
	}
	root := reflect.New(reflect.TypeOf(&value).Elem()).Elem()
	deepCopy(root, reflect.ValueOf(&value).Elem())
	f := &fitter{report: report, whole: whole, test: func() error { return check(root.Interface().(T)) }}
	if ok, culprit, why := f.fit(root, ""); !ok {
		var zero T
		if culprit == "" {
			culprit = "reply"
		}
		return zero, &Error{Path: culprit, Why: why}
	}
	return root.Interface().(T), nil
}

type fitter struct {
	test   func() error
	report func(string)
	whole  bool
}

// list is one list field reachable from a value without passing through
// another list, with the entries it held before fit emptied it.
type list struct {
	v     reflect.Value
	path  string
	saved reflect.Value
}

// fit makes v, an addressable part of the reply, acceptable in place. It
// empties every list v reaches; when the reply still fails, the fault is in
// v's own fields, and fit restores v and reports the field that fails. Else
// it restores each list entry by entry.
func (f *fitter) fit(v reflect.Value, path string) (ok bool, culprit, why string) {
	lists := f.lists(v, path, nil)
	for _, l := range lists {
		l.v.Set(reflect.MakeSlice(l.v.Type(), 0, 0))
	}
	if err := f.test(); err != nil {
		culprit = f.locate(v, path)
		for _, l := range lists {
			l.v.Set(l.saved)
		}
		return false, culprit, word(err)
	}
	for _, l := range lists {
		f.restore(l)
	}
	if err := f.test(); err != nil {
		return false, name(path), word(err)
	}
	return true, "", ""
}

func (f *fitter) lists(v reflect.Value, path string, out []list) []list {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			out = f.lists(v.Elem(), path, out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if !field.CanSet() {
				continue
			}
			at := join(path, snake(t.Field(i).Name))
			if isList(field.Type()) {
				if field.Len() > 0 {
					saved := reflect.New(field.Type()).Elem()
					saved.Set(field)
					out = append(out, list{v: field, path: at, saved: saved})
				}
				continue
			}
			out = f.lists(field, at, out)
		}
	}
	return out
}

// restore puts l's entries back. Entries that fit together go back in
// halves; an entry that fails is repaired in place by fit or dropped; an
// entry that fits alone but not after the kept ones means the list or the
// reply is full, and the list is cut there.
func (f *fitter) restore(l list) {
	n := l.saved.Len()
	l.v.Set(l.saved)
	if f.test() == nil {
		return
	}
	kept := reflect.MakeSlice(l.v.Type(), 0, n)
	cut := -1
	var place func(lo, hi int)
	place = func(lo, hi int) {
		if cut >= 0 || lo >= hi {
			return
		}
		trial := reflect.AppendSlice(kept, l.saved.Slice(lo, hi))
		l.v.Set(trial)
		if f.test() == nil {
			kept = trial
			return
		}
		if hi-lo > 1 {
			mid := lo + (hi-lo)/2
			place(lo, mid)
			place(mid, hi)
			return
		}
		alone := reflect.MakeSlice(l.v.Type(), 1, 1)
		alone.Index(0).Set(l.saved.Index(lo))
		l.v.Set(alone)
		if f.test() == nil {
			cut = lo
			l.v.Set(kept)
			return
		}
		trial = reflect.Append(kept, l.saved.Index(lo))
		l.v.Set(trial)
		at := fmt.Sprintf("%s[%d]", l.path, lo)
		var ok bool
		var culprit, why string
		if f.whole {
			culprit, why = at, word(f.test())
		} else {
			ok, culprit, why = f.fit(l.v.Index(kept.Len()), at)
		}
		if ok {
			kept = trial
			return
		}
		if culprit == "" {
			culprit = at
		}
		f.report(fmt.Sprintf("field:%s:%s; dropped %s", culprit, why, at))
		l.v.Set(kept)
	}
	place(0, n)
	l.v.Set(kept)
	if cut >= 0 {
		f.report(fmt.Sprintf("field:%s:reply_bound; kept %d of %d entries", l.path, kept.Len(), n))
	}
}

// locate names the field of v the reply fails on: the first scalar whose
// zero value makes the reply pass. It returns v's own path when no single
// scalar does.
func (f *fitter) locate(v reflect.Value, path string) string {
	var found string
	var walk func(v reflect.Value, path string) bool
	walk = func(v reflect.Value, path string) bool {
		switch v.Kind() {
		case reflect.Pointer:
			return !v.IsNil() && walk(v.Elem(), path)
		case reflect.Struct:
			t := v.Type()
			for i := 0; i < v.NumField(); i++ {
				if field := v.Field(i); field.CanSet() && walk(field, join(path, snake(t.Field(i).Name))) {
					return true
				}
			}
			return false
		case reflect.Slice, reflect.Map, reflect.Array, reflect.Interface, reflect.Func, reflect.Chan:
			return false
		}
		if !v.CanSet() || v.IsZero() {
			return false
		}
		saved := reflect.New(v.Type()).Elem()
		saved.Set(v)
		v.Set(reflect.Zero(v.Type()))
		passed := f.test() == nil
		v.Set(saved)
		if passed {
			found = path
		}
		return passed
	}
	if walk(v, path) {
		return found
	}
	return name(path)
}

func isList(t reflect.Type) bool {
	return t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8
}

func name(path string) string {
	if path == "" {
		return "reply"
	}
	return path
}

func join(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}

// snake turns a generated Go field name into its wire name: CacheAgeMs is
// cache_age_ms and ID is id.
func snake(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		if unicode.IsUpper(r) {
			if i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// word is a generated reader's refusal word (its Word field) when err has
// one, else err's text.
func word(err error) string {
	v := reflect.ValueOf(err)
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && !v.IsNil() {
		v = v.Elem()
	}
	if v.IsValid() && v.Kind() == reflect.Struct {
		if w := v.FieldByName("Word"); w.IsValid() && w.Kind() == reflect.String && w.String() != "" {
			return w.String()
		}
	}
	return err.Error()
}

// deepCopy copies src into dst, giving dst its own slices and pointees so
// that fitting never writes through to the caller's value. Maps and their
// contents are shared: fit never writes into a map.
func deepCopy(dst, src reflect.Value) {
	dst.Set(src)
	switch src.Kind() {
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			if dst.Field(i).CanSet() {
				deepCopy(dst.Field(i), src.Field(i))
			}
		}
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := 0; i < src.Len(); i++ {
			deepCopy(s.Index(i), src.Index(i))
		}
		dst.Set(s)
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		p := reflect.New(src.Elem().Type())
		deepCopy(p.Elem(), src.Elem())
		dst.Set(p)
	}
}
