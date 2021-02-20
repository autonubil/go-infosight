package infosight

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	defaultVersion string = "v1"
)

type Wellness struct {
	*Client

	Version string
}

func NewWellness(client *Client) *Wellness {
	return &Wellness{
		client,
		defaultVersion,
	}
}

// GetObjectSet fetches a list of objects
// url.Values
func (w *Wellness) GetObjectSet(objectSet string) (interface{}, error) {
	queryURL := fmt.Sprintf("%swellness/%s/%s?domain=urn:nimble", w.Server, w.Version, objectSet)
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return nil, err
	}

	r, err := w.do(req)

	if err != nil {
		return nil, err
	}

	if r.StatusCode > 399 {
		return NewFaultResponse(r)
	}

	var apiResponse APIResponse
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&apiResponse)
	if err != nil {
		return nil, err
	}

	return apiResponse, err
}

func (w *Wellness) GetIssues() (interface{}, error) {
	return w.GetObjectSet("issues")
}
