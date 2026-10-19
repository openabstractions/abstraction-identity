package profile

import (
	"github.com/openabstractions/abstraction-identity/internal/personfolders"
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(personfolders.Main(m)) }
