package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func Handler(request events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	message := "Hello World!"

	if request.RequestContext.HTTP.Method == "POST" {
		message = "You sent: "

		body := request.Body
		if request.IsBase64Encoded {
			d, _ := base64.StdEncoding.DecodeString(body)
			body = string(d)
		}
		var fields map[string]string
		err := json.Unmarshal([]byte(body), &fields)

		if err == nil && len(fields) > 0 {
			message += "\n\n"
			for k, v := range fields {
				message += fmt.Sprintf("%s: %s\n", k, v)
			}
		} else {
			message += "nothing"
		}

	}

	return events.LambdaFunctionURLResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       message,
	}, nil
}

func main() {
	lambda.Start(Handler)
}
