package client

type ClientError struct {
	Component string
	Error     error
}
