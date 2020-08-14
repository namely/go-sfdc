package sfdc

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestError_UnmarshalJSON(t *testing.T) {
	type fields struct {
		ErrorCode string
		Message   string
		Fields    []string
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Error
		wantErr bool
	}{
		{
			name:   "Success with Status Code",
			fields: fields{},
			args: args{
				data: []byte(`
				{
					"statusCode" : "MALFORMED_ID",
					"message" : "Contact ID: id value of incorrect type: 001xx000003DGb2999",
					"fields" : [
					   "Id"
					]
				 }`),
			},
			want: &Error{
				ErrorCode: "MALFORMED_ID",
				Message:   "Contact ID: id value of incorrect type: 001xx000003DGb2999",
				Fields:    []string{"Id"},
			},
			wantErr: false,
		},
		{
			name:   "Success with Error Code",
			fields: fields{},
			args: args{
				data: []byte(`
				{
					"fields" : [ "Id" ],
					"message" : "Account ID: id value of incorrect type: 001900K0001pPuOAAU",
					"errorCode" : "MALFORMED_ID"
				  }`),
			},
			want: &Error{
				ErrorCode: "MALFORMED_ID",
				Message:   "Account ID: id value of incorrect type: 001900K0001pPuOAAU",
				Fields:    []string{"Id"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Error{
				ErrorCode: tt.fields.ErrorCode,
				Message:   tt.fields.Message,
				Fields:    tt.fields.Fields,
			}
			if err := e.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Error.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type alwaysError struct{}

func (alwaysError) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestHandleError(t *testing.T) {
	const (
		singleErr       = "{\"message\":\"invalid record id\",\"errorCode\":\"INVALID_ID_FIELD\",\"fields\":[\"id\"]}"
		singleErrBody   = "[" + singleErr + "]"
		multipleErrBody = "[" + singleErr + "," + singleErr + "]"
	)

	tests := map[string]struct {
		resp    *http.Response
		wantErr string
	}{
		"single_error": {
			resp: &http.Response{
				Status: "400 " + http.StatusText(400),
				Body:   ioutil.NopCloser(strings.NewReader(singleErrBody)),
			},
			wantErr: `400 Bad Request: ` + singleErrBody,
		},
		// TODO(vtopc): remove next case if SF API is never sending multiple errors:
		"multiple_error": {
			resp: &http.Response{
				Status: "400 " + http.StatusText(400),
				Body:   ioutil.NopCloser(strings.NewReader(multipleErrBody)),
			},
			wantErr: `400 Bad Request: ` + multipleErrBody,
		},
		"read_body_error": {
			resp: &http.Response{
				Status: "500 " + http.StatusText(500),
				Body:   ioutil.NopCloser(alwaysError{}),
			},
			wantErr: `500 Internal Server Error: could not read the body with error: unexpected EOF`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := HandleError(tt.resp)
			t.Log("err:", err)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}
