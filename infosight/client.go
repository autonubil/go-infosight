package infosight

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	defaultServer string = "https://infosight.hpe.com/apis/"
)

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// WithTrace write all requests to the log
func WithTrace(trace bool) ClientOption {
	return func(c *Client) error {
		c.trace = trace
		return nil
	}
}

// WithUserAgent specify a user agent string to identify the client
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) error {
		c.userAgent = userAgent
		return nil
	}
}

// WithContext specifies the credentials for
func WithContext(ctx context.Context) ClientOption {
	return func(c *Client) error {
		c.ctx = ctx
		return nil
	}
}

// WithLogin specifies the credentials for
func WithLogin(user string, password string) ClientOption {
	return func(c *Client) error {
		c.user = user
		c.password = password
		return nil
	}
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// HTTPRequestDoer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HTTPRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// FaultDetail detailed fault information
type FaultDetail struct {
	ErrorCode string `json:"errorcode,omitempty"`
}

// Fault returned if something went wrong
type Fault struct {
	FaultString string       `json:"faultstring,omitempty"`
	Detail      *FaultDetail `json:"detail,omitempty"`
}

// FaultResponse is returned by InfoSight
type FaultResponse struct {
	Status     string
	StatusCode int
	Fault      *Fault `json:"fault,omitempty"`
}

// NewFaultResponse create a new NewFaultResponse from an http response
func NewFaultResponse(r *http.Response) (*FaultResponse, error) {
	var faultResponse FaultResponse
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&faultResponse)
	if err != nil {
		return nil, err
	}
	faultResponse.Status = r.Status
	faultResponse.StatusCode = r.StatusCode
	return &faultResponse, nil
}

func (e *FaultResponse) Error() string {
	if e.Fault != nil {
		return e.Fault.FaultString
	}
	return e.Status
}

// Status result status
type Status struct {
	Message string `json:"message,omitempty"`
}

// PagingInfo request details
type PagingInfo struct {
	Skip  int `json:"skip,omitempty"`
	Limit int `json:"limit,omitempty"`
}

// FilterInfo filter details
type FilterInfo struct {
	Query map[string]string `json:"query,omitempty"`
}

type Order []string
type Sorting []Order

// RequestInfo request details
type RequestInfo struct {
	Paging *PagingInfo `json:"paging,omitempty"`
	Filter *FilterInfo `json:"filter,omitempty"`
	Sort   *Sorting    `json:"sort,omitempty"`
}

// APIResponse returned on success
type APIResponse struct {
	Status  *Status      `json:"status,omitempty"`
	Request *RequestInfo `json:"request,omitempty"`

	Data []interface{} `json:"data,omitempty"`
}

// Client wraps the api for you
type Client struct {
	Server string

	Wellness *Wellness

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	innerClient HTTPRequestDoer

	oauthConfig *clientcredentials.Config
	ctx         context.Context
	userAgent   string
	token       *oauth2.Token
	user        string
	password    string
	insecure    bool
	trace       bool
}

// NewClientFromEnvironment creates a new client from default environment variables
func NewClientFromEnvironment(opts ...ClientOption) (*Client, error) {
	baseURL := os.Getenv("INFOSIGHT_URL")
	user := os.Getenv("INFOSIGHT_CLIENT_KEY")
	password := os.Getenv("INFOSIGHT_CLIENT_SECRET")
	opts = append(opts, WithLogin(user, password))

	c, err := NewClient(baseURL, opts...)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// NewClient returns a new wazuh API client
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	// remove trailing slash (if any) from base URL
	baseURL = strings.TrimRight(baseURL, "/")

	c := &Client{
		Server:    baseURL,
		userAgent: "go-infosight",
	}

	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}

	if c.ctx == nil {
		c.ctx = context.Background()
	}

	var transport http.RoundTripper = &BearerAuthTransport{http.DefaultTransport}
	// Override default HTTP client in ctx
	c.ctx = context.WithValue(c.ctx, oauth2.HTTPClient, &http.Client{Transport: transport})

	if c.Server == "" {
		c.Server = defaultServer
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(c.Server, "/") {
		c.Server += "/"
	}

	c.oauthConfig = &clientcredentials.Config{
		ClientID:     c.user,
		ClientSecret: c.password,
		TokenURL:     c.Server + "oauth/token",
		Scopes:       []string{""},
	}

	c.innerClient = c.oauthConfig.Client(c.ctx)
	c.Wellness = NewWellness(c)
	return c, nil
}

// Errorf logs errors
func (c *Client) Errorf(format string, v ...interface{}) {
	log.Printf("[ERROR] %s", fmt.Sprintf(format, v...))
}

// Warnf logs warnings
func (c *Client) Warnf(format string, v ...interface{}) {
	log.Printf("[WARN] %s", fmt.Sprintf(format, v...))
}

// Debugf logs debug info
func (c *Client) Debugf(format string, v ...interface{}) {
	log.Printf("[DEBUG] %s", fmt.Sprintf(format, v...))
}

// Tracef logs trace info
func (c *Client) Tracef(format string, v ...interface{}) {
	log.Printf("[TRACE] %s", fmt.Sprintf(format, v...))
}

// do execute and evaluate the request
func (c *Client) do(req *http.Request) (*http.Response, error) {
	// ensure we have a valid token
	/*
		if c.token == nil {
			token, err := c.oauthConfig.Token(c.ctx)
			if err != nil {
				return nil, err
			}
			c.token = token
		}

		c.token.TokenType = "Bearer"
	*/
	req.WithContext(c.ctx)
	// Headers for all request
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	r, e := c.innerClient.Do(req)
	if c.trace {
		var reqStr = ""
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			reqStr = strings.ReplaceAll(strings.TrimRight(string(dump), "\r\n"), "\n", "\n                            ")
		}
		if r == nil {
			dump = nil
			err = nil
		} else {
			dump, err = httputil.DumpResponse(r, true)
		}
		if err == nil {
			c.Tracef("%s\n\n                            %s\n", reqStr, strings.ReplaceAll(strings.TrimRight(string(dump), "\r\n"), "\n", "\n                            "))
		}
	}
	return r, e
}

/* Workaround for wrong token type returned by InfoSight (BearerToken, but expects Bearer in auth header)
https://sgeb.io/posts/2015/05/fix-go-oauth2-case-sensitive-bearer-auth-headers/
*/

// BearerAuthTransport wraps a RoundTripper. It capitalized bearer token
// authorization headers.
type BearerAuthTransport struct {
	rt http.RoundTripper
}

// RoundTrip satisfies the RoundTripper interface. It replaces authorization
// headers of scheme `BearerToken` by changing it to `Bearer` (as per OAuth 2.0 spec).
func (t *BearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "BearerToken ") {
		auth = "Bearer " + auth[12:]
	}

	req2 := cloneRequest(req) // per RoundTripper contract
	req2.Header.Set("Authorization", auth)

	return t.rt.RoundTrip(req2)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
