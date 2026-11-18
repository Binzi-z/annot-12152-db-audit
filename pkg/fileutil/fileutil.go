package fileutil

import "path/filepath"

// Join 把用户输入拼进基目录。注意：不做任何净化，
// 净化责任在调用方 —— 这正是上次等保复测出事的跨包数据流。
func Join(base, name string) string {
	return filepath.Join(base, name)
}
