// Package tests @notice Holds every test and runnable example in the module.
//
// @dev The tests live here rather than beside their packages, so each one exercises kal across
// a real package boundary — exactly as a consumer does. Nothing in this directory can reach an
// unexported symbol, which means a test passing here proves the exported surface is sufficient.
// For an auth library that rule has teeth: if a security property cannot be asserted from out
// here, a consumer cannot rely on it either, and the exported surface — not the test — is what
// has to change.
//
// The cost, stated plainly: Example functions do not render on pkg.go.dev under the symbols
// they demonstrate, because godoc binds an example to a symbol by directory. They still compile
// and their Output blocks still run, so they cannot rot — they are simply not published.
package tests
