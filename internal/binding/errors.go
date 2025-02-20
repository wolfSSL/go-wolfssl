package binding

// WolfSSLError represents an error from the wolfSSL library
type WolfSSLError int32

func (e WolfSSLError) Error() string {
    return "wolfSSL error"
}
