package gomitm

import "testing"

func TestUseH2(t *testing.T) {
	if !useH2("h2") {
		t.Fatal(`useH2("h2") want true`)
	}
	if useH2("http/1.1") {
		t.Fatal(`useH2("http/1.1") want false`)
	}
	if useH2("") {
		t.Fatal(`useH2("") want false`)
	}
}
