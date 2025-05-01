package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/abakum/ftype"
	"golang.org/x/sys/windows"
)

func main() {
	//ft a="b" "c"
	assoc := strings.TrimPrefix(ftype.GetCommandLine(), os.Args[0])
	// a="b" "c"
	assoc = strings.TrimSpace(assoc)
	//a="b" "c"
	if assoc != "" {
		if assoc == "/?" || strings.Contains(assoc, "=") {
			const ft = "ftype"
			// Помощь и изменения progId пусть делает `ftype`
			if cleanUp := ftype.AntiLoop(); cleanUp != nil {
				defer cleanUp()
			} else {
				fmt.Println("Комманда", ft, "уже запущена")
				return
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
		progId, command := ftype.Assoc2progIdCommand(assoc)
		xa := ftype.Assoc2xa(assoc, " ")
		a := assoc
		if xa == "" {
			a = progId
		}
		s := "протокола"
		if progId == "" {
			switch xa {
			case "":
			case " ":
				s = "расширения имени файла"
				fallthrough
			default:
				fmt.Printf("Не найдено сопоставление для %s '%s'.\r\n", s, a)
				return
			}
		}
		if command == "" {
			apc(assoc, progId, command)
			switch xa {
			case " ":
				s = "Файлу"
			case "":
				s = "Типу"
				a = assoc
			default:
				s = "Протоколу"
			}
			fmt.Printf("%s '%s' не сопоставлена команда открытия.\r\n", s, a)
			return
		}
		apc(assoc, progId, command)
		return
	}

	ftype.EnumClassesRoot(apc, ftype.IsAssoc)
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
