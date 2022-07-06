package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hillu/go-yara/v4"
)

//go:embed rules/*
var rules embed.FS
var scanner yara.Scanner

func main() {
	buildRules()

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	f, _ := os.Create("/var/log/golang/golang-server.log")
	defer f.Close()
	// log.SetOutput(f)

	const indexPage = "public/index.html"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
		} else {
			fmt.Fprintf(w, "up, requested at %s", time.Now().Format(time.RFC1123))
		}
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.NotFound(w, r)
		} else {
			text := r.FormValue("text")
			fmt.Fprintf(w, "scanning '%s'", text)
			scan(text)
		}
	})

	log.Printf("Listening on port %s\n\n", port)
	http.ListenAndServe(":"+port, nil)
}

func buildRules() {
	ruleFiles, err := rules.ReadDir("rules")
	if err != nil {
		log.Fatal(err)
	}

	ruleText := ""
	for _, v := range ruleFiles {
		data, err := rules.ReadFile("rules/" + v.Name())
		if err != nil {
			log.Fatal(v.Name(), err)
		}
		ruleText = ruleText + string(data)
	}

	externals := map[string]interface{}{"filename": ""}
	rulesCompiled, err := yara.Compile(ruleText, externals)
	if err != nil {
		log.Fatal("compiling", err)
	}

	scannerCandidate, err := yara.NewScanner(rulesCompiled)
	if err != nil {
		log.Fatal(err)
	}

	scanner = *scannerCandidate
}

func scan(text string) {

}
