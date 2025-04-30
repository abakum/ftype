package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	DIRMODE         = 0755
	FILEMODE        = 0644
	ft              = "ftype"
	sc              = `SOFTWARE\Classes`
	sra             = `SOFTWARE\RegisteredApplications`
	sa              = `SOFTWARE\Microsoft\Windows\Shell\Associations`
	row             = `SOFTWARE\Microsoft\Windows\Roaming\OpenWith`
	cve             = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`
	ua              = "UrlAssociations"
	fa              = `FileAssociations`
	fe              = "FileExts"
	access   uint32 = registry.READ
	try             = 10000
)

var (
	tmp = os.TempDir()
	_   = os.MkdirAll(tmp, DIRMODE)
)

func main() {
	//ft a="b" "c"
	assoc := strings.TrimPrefix(GetCommandLine(), os.Args[0])
	// a="b" "c"
	assoc = strings.TrimSpace(assoc)
	//a="b" "c"
	if assoc != "" {
		if assoc == "/?" || strings.Contains(assoc, "=") {
			e, err := os.Executable()
			// path/type.exe
			if err != nil {
				e = ft
				// type
			} else {
				e = filepath.Base(e)
				// type.exe
				e = strings.Split(e, ".")[0]
				// type
			}
			antiLoop := filepath.Join(tmp, e)
			if isFileExist(antiLoop) {
				return
			}
			if os.WriteFile(antiLoop, []byte{}, FILEMODE) == nil {
				defer os.Remove(antiLoop)
			}
			opts := []string{"/c", ft, assoc}
			cmd := exec.Command("cmd", opts...)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				CmdLine: strings.Join(opts, " "),
			}
			fmt.Println(cmd)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			fmt.Println("Press Enter")
			b := []byte{0}
			os.Stdin.Read(b)
			return
		}
		progId, command := assoc2progId(assoc)
		if command == "" {
			progId, _ = GetStringValue(registry.CLASSES_ROOT,
				assoc, "")
			if progId != "" {
				_, command = assoc2progId(progId)
			}
			if command == "" {
				fmt.Printf("Тип файлов '%s' не найден, или ему не сопоставлена команда открытия.\r\n", assoc)
				return
			}
		}
		if progId != "" {
			progId = "=" + progId
		}
		fmt.Println(assoc + progId + "=" + command)
		return
	}

	fileURLs, _ := registry.CLASSES_ROOT.ReadSubKeyNames(try)
	// fmt.Println(len(fileURLs))
	for _, fileURL := range fileURLs {
		progId, command := "", ""
		def, _ := GetStringValue(registry.CLASSES_ROOT,
			fileURL, "")
		if strings.HasPrefix(def, "URL:") {
			progId, command = assoc2progId(fileURL)
		} else if strings.HasPrefix(fileURL, ".") {
			progId, command = assoc2progId(fileURL)
			if command == "" {
				_, command = assoc2progId(def)
				progId = def
			}
		}
		if command != "" {
			if progId != "" {
				progId = "=" + progId
			}
			fmt.Println(fileURL + progId + "=" + command)
		}
	}
}

func isFileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return true
}

func GetCommandLine() string {
	return windows.UTF16PtrToString(syscall.GetCommandLine())
}

func GetStringValue(r registry.Key, path, k string) (v string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} { // , access | registry.WOW64_64KEY
		key, err = registry.OpenKey(r, path, a)
		if err == nil {
			defer key.Close()
			break
		}
	}
	// fmt.Println(r, key, path, k, v, err)
	if err != nil {
		return
	}
	v, _, err = key.GetStringValue(k)
	return
}

func ReadValueNames(r registry.Key, path string, n int) (names []string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} { //, access | registry.WOW64_64KEY
		key, err = registry.OpenKey(r, path, a)
		if err == nil {
			defer key.Close()
			break
		}
	}
	if err != nil {
		return
	}
	return key.ReadValueNames(n)
}

func progId2command(progId string) (command string, err error) {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		command, err = GetStringValue(root,
			filepath.Join(sc, progId, "shell", "open", "command"), "")
		if err == nil {
			return
		}
	}
	return
}

func assoc2progIds(assoc string) (progIds []string, err error) {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		var RegisteredApplications []string
		RegisteredApplications, err = ReadValueNames(root,
			sra, 0)
		if err != nil || len(RegisteredApplications) < 1 {
			continue
		}
		Capabilities := ""
		xa := assoc2xa(assoc, fa)
		for _, RegisteredApplication := range RegisteredApplications {
			// WinSCP
			Capabilities, err = GetStringValue(root,
				sra, RegisteredApplication)
			// Software\Martin Prikryl\WinSCPCapabilities
			if err != nil || Capabilities == "" {
				continue
			}
			progId, err := GetStringValue(root,
				filepath.Join(Capabilities, xa),
				assoc)
			if err != nil || progId == "" {
				continue
			}
			progIds = append(progIds, progId)
		}
	}
	return
}

// Файл или URL
func assoc2xa(assoc, fa string) string {
	if strings.HasPrefix(assoc, ".") {
		return fa
	}
	return ua
}

func assoc2progId(assoc string) (progId, command string) {
	xs := []string{sa, row}
	xa := assoc2xa(assoc, fe)
	if strings.HasPrefix(assoc, ".") {
		xs = []string{cve, row}
	}

	for _, x := range xs {
		progId, _ = GetStringValue(registry.CURRENT_USER,
			filepath.Join(x, xa, assoc, "UserChoice"),
			"ProgId")
		if progId != "" {
			break
		}
	}
	if progId != "" {
		command, _ = progId2command(progId)
		// fmt.Println(bin, err)
	}
	if command == "" {
		progIds, _ := assoc2progIds(assoc)
		// fmt.Println(progIds, err)
		if len(progIds) < 1 {
			progIds = []string{assoc}
		}
		for _, progId := range progIds {
			command, _ = progId2command(progId)
			// fmt.Println(bin, err)
			if command != "" {
				break
			}
		}
	}
	return
}
