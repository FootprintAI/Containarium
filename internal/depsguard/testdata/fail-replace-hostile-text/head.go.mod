module example.com/fixture

go 1.26

require golang.org/x/text v0.3.8

// Explanatory comment, as on the real grpc pin: kept because a fixed
// release is not tagged yet.
replace google.golang.org/grpc => google.golang.org/grpc v1.83.2

// Hostile replace target: a quoted local path may hold a newline, a
// workflow command, a mention, a link, raw HTML and backticks.
replace golang.org/x/text => "./x\n::warning title=pwned::injected annotation @someone [Click to approve](https://evil.example/x) <img src=x> `` ` --> |"
