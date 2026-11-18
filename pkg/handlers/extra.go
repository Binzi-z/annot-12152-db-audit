package handlers

import (
	"net/http"

	"annot/pkg/fileutil"
)

// Handle14 影像下载接口：文件名来自查询串，跨包拼路径后直接打开（CWE-22）。
func Handle14(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := fileutil.Join(baseDir, raw)
	_ = readFile(v)
}
