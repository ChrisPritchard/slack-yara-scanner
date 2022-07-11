package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

type Request struct {
	RequestContext  RequestContext `json:"requestContext"`
	Body            string         `json:"body"`
	IsBase64Encoded bool           `json:"isBase64Encoded"`
}

type RequestContext struct {
	Http HttpDetails `json:"http"`
}

type HttpDetails struct {
	Method string `json:"method"`
}

type Response struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func Handler(request Request) (Response, error) {
	message := "Hello World!"

	if request.RequestContext.Http.Method == "POST" {
		message = "You sent: "

		body := request.Body
		if request.IsBase64Encoded {
			d, _ := base64.StdEncoding.DecodeString(body)
			body = string(d)
		}
		var fields map[string]string
		err := json.Unmarshal([]byte(body), &fields)

		if err == nil && len(request.Body) > 0 {
			message += "\n\n"
			for k, v := range fields {
				message += fmt.Sprintf("%s: %s\n", k, v)
			}
		} else {
			message += "nothing"
		}

	}

	return Response{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       message,
	}, nil
}

func main() {
	lambda.Start(Handler)
}
