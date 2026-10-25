module example.com/fixture

go 1.26

require (
	example.com/deps-guard-fixture/absent v1.0.0
	golang.org/x/text v0.3.8
)

// Explanatory comment, as on the real grpc pin: kept because a fixed
// release is not tagged yet.
replace google.golang.org/grpc => google.golang.org/grpc v1.83.2
