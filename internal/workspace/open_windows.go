package workspace

import (
	"os"
	"syscall"
)

func openFileNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	// Check the opened handle before truncating any existing file.
	f, err := os.OpenFile(path, flags&^os.O_TRUNC|syscall.FILE_FLAG_OPEN_REPARSE_POINT, perm)
	if err != nil {
		return nil, err
	}
	var info syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info)
	if err == nil && info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		err = os.ErrPermission
	}
	if err != nil {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if flags&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}
