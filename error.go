package sfdc

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

// Error is the error structure defined by the Salesforce API.
type Error struct {
	ErrorCode string   `json:"errorCode"`
	Message   string   `json:"message"`
	Fields    []string `json:"fields"`
}

// UnmarshalJSON will unmarshal a JSON byte array.
func (e *Error) UnmarshalJSON(data []byte) error {
	if e == nil {
		return errors.New("record: can't unmarshal to a nil struct")
	}

	var jsonMap map[string]interface{}
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		return err
	}

	if code, ok := jsonMap["statusCode"]; ok {
		if codeStr, ok := code.(string); ok {
			e.ErrorCode = codeStr
		} else {
			return errors.New("json error: statusCode is not a string")
		}
	}
	if code, ok := jsonMap["errorCode"]; ok {
		if codeStr, ok := code.(string); ok {
			e.ErrorCode = codeStr
		} else {
			return errors.New("json error: errorCode is not a string")
		}
	}
	if message, ok := jsonMap["message"]; ok {
		if messageStr, ok := message.(string); ok {
			e.Message = messageStr
		} else {
			return errors.New("json error: message is not a string")
		}
	}
	if fields, ok := jsonMap["fields"]; ok {
		if array, has := fields.([]interface{}); has {
			e.Fields = make([]string, len(array))
			for idx, element := range array {
				if field, ok := element.(string); ok {
					e.Fields[idx] = field
				} else {
					return errors.New("json error: field element is not a string")
				}
			}
		} else {
			return errors.New("json error: fields is not an array")
		}
	}
	return nil
}

// HandleError makes an error from http.Response.
// It is the caller's responsibility to close resp.Body.
func HandleError(resp *http.Response) error {
	return errors.Wrap(newErrorFromBody(resp), resp.Status)
}

func newErrorFromBody(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "could not read the body with error")
	}

	return errors.New(string(body))
}
