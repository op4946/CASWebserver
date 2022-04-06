package main

import (
	"fmt"
	"net/http"// Built in http webserver
	"html/template"
	"database/sql"

	"github.com/julienschmidt/httprouter"// Third party router to provide extra features
	_ "github.com/mattn/go-sqlite3"//		SQLite driver
)

var sqldb *sql.DB

func Index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	err := templates.ExecuteTemplate(w, "home.html", nil)
	if err != nil {
		fmt.Println("Err serving / : ", err)
		return
	}
}

func HandlerSaveURL(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.ParseForm()

	statment, _ := sqldb.Prepare("INSERT INTO urls (url) VALUES (?)")

	statment.Exec(r.PostForm["URL"][0])

	http.Redirect(w, r, "/urls", http.StatusSeeOther)
}

func HanderViewURLs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var templateData = struct {
		URLs []string
	}{ }

	rows, _ := sqldb.Query("SELECT url FROM urls")
	defer rows.Close()
	var tmpurl string
	for rows.Next() {
		rows.Scan(&tmpurl)
		templateData.URLs = append(templateData.URLs, tmpurl)
	}

	err := templates.ExecuteTemplate(w, "viewurls.html", templateData)
	if err != nil {
		fmt.Println("Error executing template while serving /urls: ", err)
		fmt.Fprint(w, "An error occured")
	}
	
}

func RedirectWrapper(path string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		http.Redirect(w, r, path, http.StatusMovedPermanently)
		return
	}
}

var templates *template.Template

func main() {
	router := httprouter.New()// Init httprouter

	var err error
	sqldb, err = sql.Open("sqlite3", "database.db")//	Open our main database
	if err != nil {
		fmt.Println("Error opening sqldatabase: ", err)
		return
	}

	templates, err = template.ParseGlob("templates/*")
	if err != nil {
		fmt.Println("Error parsing templates: ", err)
		return
	}

	router.GET("/", Index)
	router.GET("/saveurl", RedirectWrapper("/pages/saveurl"))
	router.POST("/saveurl", HandlerSaveURL)
	router.GET("/urls", HanderViewURLs)
	router.ServeFiles("/pages/*filepath", http.Dir("static/"))


	fmt.Println("Server started on localhost:8080")// Notifies me that its finished compiling
	http.ListenAndServe("localhost:8080", router);// Start server on localhost:8080
}
