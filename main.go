package main

import (
	"fmt"
	"net/http"// Built in http webserver

	"github.com/julienschmidt/httprouter"// Third party router to provide extra features
)

func Index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fmt.Fprint(w, "Welcome!");
}

func main() {
	router := httprouter.New()// Init httprouter
	router.GET("/", Index)

	fmt.Println("Server started on localhost:8080")// Notifies me that its finished compiling
	http.ListenAndServe("localhost:8080", router);// Start server on localhost:8080
}
