package crawler

import "os"

// logWriter is where verbose crawler output goes (stderr so it doesn't pollute stdout)
var logWriter = os.Stderr
