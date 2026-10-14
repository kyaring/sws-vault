package panel

import (
	"html/template"
	"net/http"
	"strings"
)

func Render(w http.ResponseWriter, src string, data any) {
	src = strings.Replace(src, "<meta charset=\"utf-8\">", "<meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\">", 1)
	t, e := template.New("page").Parse(src)
	if e != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e = t.Execute(w, data); e != nil {
		return
	}
}
