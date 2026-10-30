module example.com/fixture

go 1.26

require (
	golang.org/x/text v0.3.8
	gopkg.in/yaml.v3 v3.0.1
)

// Explanatory comment, as on the real grpc pin: kept because a fixed
// release is not tagged yet.
replace google.golang.org/grpc => google.golang.org/grpc v1.83.2
