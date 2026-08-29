package buildinfo

// Version is injected by the release build. Development builds deliberately
// share this explicit value across the scanner and broker.
var Version = "0.0.0-dev"

const ProtocolVersion = "1.0.0"
