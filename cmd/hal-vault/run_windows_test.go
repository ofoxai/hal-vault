package main

import "os"

// waitForSignal is unused on Windows, where run cannot forward signals.
func waitForSignal() { os.Exit(3) }
