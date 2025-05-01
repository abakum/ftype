package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
			// Помощь и изменения progId пусть делает `ftype`
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
			cmd.SysProcAttr = &windows.SysProcAttr{
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
		// assoc как расширение файла или как протокол в URL для `assoc`.
		// Или ProgId как для `ftype`.
		progId, command := assoc2progIdCommand(assoc)
		if command == "" {
			fmt.Printf("Тип файлов '%s' не найден, или ему не сопоставлена команда открытия.\r\n", assoc)
			return
		}
		apc(assoc, progId, command)
		return
	}

	assocs, _ := registry.CLASSES_ROOT.ReadSubKeyNames(0)
	for _, assoc := range assocs {
		if assoc2xa(assoc, " ") == "" {
			continue
		}
		// Дальше только файлы для Start как для `assoc`
		progId, command := assoc2progIdCommand(assoc)
		apc(assoc, progId, command)
	}
}

// Из CLASSES_ROOT.
// Как в cmd /c assoc.
func assoc2command(assoc string) (progId, command string) {
	progId, _ = GetStringValue(registry.CLASSES_ROOT, assoc, "")
	if progId == "" {
		return
	}

	if k, err := registry.OpenKey(registry.CLASSES_ROOT, progId, access); err == nil {
		k.Close()
		command, _ = progId2command(progId)
	}
	return
}

func apc(assoc, progId, command string) {
	if progId == assoc {
		progId = ""
	}
	if progId != "" {
		progId = "=" + progId
	}
	if command != "" {
		command = "=" + command
	}
	fmt.Println(assoc + progId + command)
}

// Если файл существует
func isFileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return true
}

// Сохраняем двойные кавычки для `ftype`
func GetCommandLine() string {
	return windows.UTF16PtrToString(windows.GetCommandLine())
}

// К GetStringValue добавлено чтение из WOW64_32KEY
func GetStringValue(r registry.Key, path, k string) (v string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} {
		key, err = registry.OpenKey(r, path, a)
		if err == nil {
			defer key.Close()
			break
		}
	}
	if err != nil {
		return
	}
	v, _, err = key.GetStringValue(k)
	return
}

// К ReadValueNames добавлено чтение из WOW64_32KEY
func ReadValueNames(r registry.Key, path string, n int) (names []string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} {
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

// Из shell\open\command.
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

// Из RegisteredApplications.
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
		if xa == "" {
			return
		}
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

// Файл, URL или нет.
func assoc2xa(assoc, fa string) string {
	if strings.HasPrefix(assoc, ".") {
		return fa
	} else if def, _ := GetStringValue(registry.CLASSES_ROOT, assoc, ""); strings.HasPrefix(def, "URL:") {
		return ua
	}
	return ""
}

// Из UserChoice.
// Из RegisteredApplications.
// Из CLASSES_ROOT.
func assoc2progIdCommand(assoc string) (progId, command string) {
	xs := []string{sa, row}
	xa := assoc2xa(assoc, fe)
	if strings.HasPrefix(assoc, ".") {
		xs = []string{cve, row}
	}
	if xa != "" {
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
		if command != "" {
			return
		}
	}
	progIds, _ := assoc2progIds(assoc)
	// fmt.Println(progIds, err)
	if len(progIds) < 1 {
		// Может assoc это progId
		progIds = []string{assoc}
	}
	for _, p := range progIds {
		progId = p
		command, _ = progId2command(progId)
		if command != "" {
			return
		}
	}
	progId, command = assoc2command(assoc)
	return
}
