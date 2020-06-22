package sfdc

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/pkg/errors"
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
	tests := map[string]struct {
		resp    *http.Response
		wantErr error
	}{
		"400": {
			resp: &http.Response{
				Status: "400 " + http.StatusText(http.StatusBadRequest),
				Body:   ioutil.NopCloser(strings.NewReader(`{"message":"invalid"}`)),
			},
			wantErr: errors.New(`400 Bad Request: {"message":"invalid"}`),
		},
		"read_body_error": {
			resp: &http.Response{
				Status: "500 " + http.StatusText(http.StatusInternalServerError),
				Body:   ioutil.NopCloser(alwaysError{}),
			},
			wantErr: errors.New(`500 Internal Server Error: could not read the body with error: unexpected EOF`),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := HandleError(tt.resp)
			if tt.wantErr != nil {
				require.EqualError(t, err, tt.wantErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
