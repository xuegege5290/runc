package utils

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

const (
	exitSignalOffset = 128
)

// NativeEndian is the native byte order of the host system.
var NativeEndian binary.ByteOrder

func init() {
	// Copied from <golang.org/x/net/internal/socket/sys.go>.
	i := uint32(1)
	b := (*[4]byte)(unsafe.Pointer(&i))
	if b[0] == 1 {
		NativeEndian = binary.LittleEndian
	} else {
		NativeEndian = binary.BigEndian
	}
}

// ExitStatus returns the correct exit status for a process based on if it
// was signaled or exited cleanly
func ExitStatus(status unix.WaitStatus) int {
	if status.Signaled() {
		return exitSignalOffset + int(status.Signal())
	}
	return status.ExitStatus()
}

// WriteJSON writes the provided struct v to w using standard json marshaling
func WriteJSON(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// CleanPath makes a path safe for use with filepath.Join. This is done by not
// only cleaning the path, but also (if the path is relative) adding a leading
// '/' and cleaning it (then removing the leading '/'). This ensures that a
// path resulting from prepending another path will always resolve to lexically
// be a subdirectory of the prefixed path. This is all done lexically, so paths
// that include symlinks won't be safe as a result of using CleanPath.
func CleanPath(path string) string {
	// Deal with empty strings nicely.
	if path == "" {
		return ""
	}

	// Ensure that all paths are cleaned (especially problematic ones like
	// "/../../../../../" which can cause lots of issues).

	//Clean函数通过单纯的词法操作返回和path代表同一地址的最短路径。

	path = filepath.Clean(path)

	// If the path isn't absolute, we need to do more processing to fix paths
	// such as "../../../../<etc>/some/path". We also shouldn't convert absolute
	// paths to relative ones.

	//IsAbs返回路径是否是一个绝对路径。

	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		// This can't fail, as (by definition) all paths are relative to root.
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}

	// Clean the path again for good measure.
	return filepath.Clean(path)
}

// stripRoot returns the passed path, stripping the root path if it was
// (lexicially) inside it. Note that both passed paths will always be treated
// as absolute, and the returned path will also always be absolute. In
// addition, the paths are cleaned before stripping the root.
func stripRoot(root, path string) string {
	// Make the paths clean and absolute.
	root, path = CleanPath("/"+root), CleanPath("/"+path)
	switch {
	case path == root:
		path = "/"
	case root == "/":
		// do nothing
		//strings.HasPrefix函数用来检测字符串是否以指定的前缀开头
	case strings.HasPrefix(path, root+"/"):
		//strings.TrimPrefix(s,str)删除s头部的prefix字符串。如果s不是以prefix开头，则返回原始s
		path = strings.TrimPrefix(path, root+"/")
	}
	return CleanPath("/" + path)
}

//fd是一个目录，里面包含着当前进程打开的每一个文件的描述符（file descriptor）差不多就是路径啦，
//这些文件描述符是指向实际文件的一个符号连接，即每个通过这个进程打开的文件都会显示在这里。所以我们可以通过fd目录的文件获取进程，从而打开每个文件的路径以及文件内容。

//这个fd比较重要，因为在Linux系统中，如果一个程序用 open() 打开了一个文件，但是最终没有关闭它，即使从外部（如：os.remove(SECRET_FILE))删除这个文件之后，
//在/proc这个进程的 pid目录下的fd文件描述符 目录下 还是会有这个文件的文件描述符，通过这个文件描述符我们即可以得到被删除的文件的内容
//原文链接：https://blog.csdn.net/Zero_Adam/article/details/114853022

// WithProcfd runs the passed closure with a procfd path (/proc/self/fd/...)
// corresponding to the unsafePath resolved within the root. Before passing the
// fd, this path is verified to have been inside the root -- so operating on it
// through the passed fdpath should be safe. Do not access this path through
// the original path strings, and do not attempt to use the pathname outside of
// the passed closure (the file handle will be freed once the closure returns).
//对需要挂载的目标路径进行合法判断
func WithProcfd(root, unsafePath string, fn func(procfd string) error) error {
	// Remove the root then forcefully resolve inside the root.
	unsafePath = stripRoot(root, unsafePath)
	path, err := securejoin.SecureJoin(root, unsafePath)
	if err != nil {
		return fmt.Errorf("resolving path inside rootfs failed: %w", err)
	}

	// Open the target path.
	fh, err := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open o_path procfd: %w", err)
	}
	defer fh.Close()

	//data, _ := os.Readlink("src") //我的linux返回的是/home/widuu/go/src
	//os.ReadLink()函数原形是func Readlink(name string) (string, error)输入的是链接的名称返回的是目标文件和err
	//进程可以通过访问/proc/self/目录来获取自己的系统信息，而不用每次都获取pid。这个目录比较独特，
	//不同的进程访问该目录时获得的信息时不同的，内容等价于/proc/本进程pid/
	// Double-check the path is the one we expected.

	//Itoa()函数用于将int类型数据转换为对应的字符串表示

	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
	if realpath, err := os.Readlink(procfd); err != nil {
		return fmt.Errorf("procfd verification failed: %w", err)
	} else if realpath != path {
		return fmt.Errorf("possibly malicious path detected -- refusing to operate on %s", realpath)
	}

	// Run the closure.
	return fn(procfd)
}

// SearchLabels searches through a list of key=value pairs for a given key,
// returning its value, and the binary flag telling whether the key exist.
func SearchLabels(labels []string, key string) (string, bool) {
	key += "="
	for _, s := range labels {
		if strings.HasPrefix(s, key) {
			return s[len(key):], true
		}
	}
	return "", false
}

// Annotations returns the bundle path and user defined annotations from the
// libcontainer state.  We need to remove the bundle because that is a label
// added by libcontainer.
func Annotations(labels []string) (bundle string, userAnnotations map[string]string) {
	userAnnotations = make(map[string]string)
	for _, l := range labels {
		parts := strings.SplitN(l, "=", 2)
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "bundle" {
			bundle = parts[1]
		} else {
			userAnnotations[parts[0]] = parts[1]
		}
	}
	return
}
